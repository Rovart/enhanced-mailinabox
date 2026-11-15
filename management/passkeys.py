# Passkeys (WebAuthn) for logging into the control panel.
#
# A passkey replaces the email address, the password and the two-factor code: the
# authenticator (a phone, a computer, a password manager or a security key) checks that
# it's the user (fingerprint, face, PIN) and signs a challenge from the box with a key
# that only works for the box's hostname. Passkeys are discoverable credentials, so the
# login page doesn't ask for the email address first: the passkey says whose it is.
#
# The verification is done by py_webauthn (https://github.com/duo-labs/py_webauthn).

import datetime
import json
import secrets
import sqlite3
import time

from expiringdict import ExpiringDict
from webauthn import generate_authentication_options, generate_registration_options, \
	options_to_json, verify_authentication_response, verify_registration_response
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, parse_authentication_credential_json, \
	parse_client_data_json, parse_registration_credential_json
from webauthn.helpers.structs import AttestationConveyancePreference, AuthenticatorSelectionCriteria, \
	AuthenticatorTransport, PublicKeyCredentialDescriptor, ResidentKeyRequirement, UserVerificationRequirement

from mailconfig import open_database
from mfa import get_user_id

# How long a challenge can be answered, in seconds. Each challenge is answered once.
CHALLENGE_TIMEOUT = 300

# Challenges sent to browsers and not answered yet, by their base64url form. The
# management daemon runs in a single process (see setup/management.sh), like its login
# sessions. Asking for login challenges doesn't need a login, so their number is limited:
# the oldest are dropped first. (Each one also says when it expires: ExpiringDict.pop()
# doesn't check the age of what it returns.)
challenges = ExpiringDict(max_len=256, max_age_seconds=CHALLENGE_TIMEOUT)

MAX_LABEL_LENGTH = 64


def get_rp_id(env):
	# The passkeys work for the box's hostname, where the control panel is.
	return env["PRIMARY_HOSTNAME"]


def get_origin(env):
	return "https://" + env["PRIMARY_HOSTNAME"]


def now():
	return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def get_passkeys(email, env):
	# The user's passkeys, as shown in the control panel.
	c = open_database(env)
	c.execute(
		'SELECT id, label, created, last_used FROM passkeys WHERE user_id=? ORDER BY id',
		(get_user_id(email, c), ))
	return [{
		"id": r[0],
		"label": r[1],
		"created": r[2],
		"last_used": r[3],
	} for r in c.fetchall()]


def passkey_exists(passkey_id, env):
	c = open_database(env)
	c.execute('SELECT 1 FROM passkeys WHERE id=?', (passkey_id, ))
	return c.fetchone() is not None


def remember_challenge(challenge, state):
	state = dict(state, challenge=challenge, expires=time.time() + CHALLENGE_TIMEOUT)
	challenges[bytes_to_base64url(challenge)] = state


def take_challenge(client_data_json, ceremony):
	# Returns what was remembered about the challenge the browser answered, and forgets
	# it, so that each answer is used once. Returns None if the challenge is unknown,
	# expired, or for another ceremony.
	try:
		client_data = parse_client_data_json(client_data_json)
	except Exception:
		return None
	state = challenges.pop(bytes_to_base64url(client_data.challenge), None)
	if state is None or state["ceremony"] != ceremony or time.time() > state["expires"]:
		return None
	return state


def parse_transports(value):
	transports = []
	for t in json.loads(value or "[]"):
		try:
			transports.append(AuthenticatorTransport(t))
		except ValueError:
			pass
	return transports or None


def get_registration_options(email, env):
	# The options for navigator.credentials.create(), to add a passkey for the user.
	c = open_database(env)
	user_id = get_user_id(email, c)
	c.execute('SELECT credential_id, transports, user_handle FROM passkeys WHERE user_id=?', (user_id, ))
	existing = c.fetchall()

	# The user handle tells which user a passkey is for. It is random (the WebAuthn
	# specification recommends against putting the email address in it) and the same for
	# all of a user's passkeys.
	user_handle = existing[0][2] if existing else bytes_to_base64url(secrets.token_bytes(32))

	options = generate_registration_options(
		rp_id=get_rp_id(env),
		rp_name=env["PRIMARY_HOSTNAME"],
		user_id=base64url_to_bytes(user_handle),
		user_name=email,
		user_display_name=email,
		timeout=CHALLENGE_TIMEOUT * 1000,
		attestation=AttestationConveyancePreference.NONE,
		authenticator_selection=AuthenticatorSelectionCriteria(
			resident_key=ResidentKeyRequirement.REQUIRED,
			user_verification=UserVerificationRequirement.REQUIRED,
		),
		# The authenticators that already have a passkey for the user don't make another.
		exclude_credentials=[
			PublicKeyCredentialDescriptor(id=base64url_to_bytes(r[0]), transports=parse_transports(r[1]))
			for r in existing
		],
	)
	remember_challenge(options.challenge, {
		"ceremony": "register",
		"email": email,
		"user_handle": user_handle,
	})
	return json.loads(options_to_json(options))


def add_passkey(email, credential_json, label, env, log):
	# Verifies the browser's answer to the registration options and saves the passkey.
	# Returns None, or why the passkey wasn't added. (Messages, not exceptions: they go to
	# the control panel as they are. The verification's details go to the log.)
	label = (label or "").strip()[:MAX_LABEL_LENGTH] or "Passkey"
	try:
		credential = parse_registration_credential_json(credential_json)
	except Exception:
		return "The browser's answer couldn't be read."

	state = take_challenge(credential.response.client_data_json, "register")
	if state is None or state["email"] != email:
		return "The request expired. Try again."

	try:
		verified = verify_registration_response(
			credential=credential,
			expected_challenge=state["challenge"],
			expected_rp_id=get_rp_id(env),
			expected_origin=get_origin(env),
			require_user_verification=True,
		)
	except Exception as e:
		log.warning("Passkey not added for %s: %s", email, one_line(e))
		return "The passkey couldn't be verified."

	transports = [t.value for t in (credential.response.transports or [])]
	conn, c = open_database(env, with_connection=True)
	try:
		c.execute(
			'INSERT INTO passkeys (user_id, credential_id, public_key, sign_count, transports, user_handle, label, created) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
			(get_user_id(email, c), bytes_to_base64url(verified.credential_id),
			bytes_to_base64url(verified.credential_public_key), verified.sign_count,
			json.dumps(transports), state["user_handle"], label, now()))
	except sqlite3.IntegrityError:
		return "This passkey was already added."
	conn.commit()
	return None


def remove_passkey(email, passkey_id, env):
	# Removes one of the user's passkeys, or all of them if passkey_id is None. Returns
	# whether any was removed. The sessions they opened end (see auth.py).
	conn, c = open_database(env, with_connection=True)
	if passkey_id is None:
		c.execute('DELETE FROM passkeys WHERE user_id=?', (get_user_id(email, c), ))
	else:
		c.execute('DELETE FROM passkeys WHERE user_id=? AND id=?', (get_user_id(email, c), passkey_id))
	conn.commit()
	return c.rowcount > 0


def get_login_options(env):
	# The options for navigator.credentials.get(), to log in with a passkey. No
	# credentials are listed: the browser offers the user's passkeys for the hostname.
	options = generate_authentication_options(
		rp_id=get_rp_id(env),
		timeout=CHALLENGE_TIMEOUT * 1000,
		user_verification=UserVerificationRequirement.REQUIRED,
	)
	remember_challenge(options.challenge, {"ceremony": "login"})
	return json.loads(options_to_json(options))


def check_passkey_login(credential_json, env, log):
	# Verifies the browser's answer to the login options. Returns the user's email address,
	# the passkey's id and None, or None, None and why the login failed.
	try:
		credential = parse_authentication_credential_json(credential_json)
	except Exception:
		return None, None, "The browser's answer couldn't be read."

	state = take_challenge(credential.response.client_data_json, "login")
	if state is None:
		return None, None, "The request expired. Try again."

	conn, c = open_database(env, with_connection=True)
	c.execute(
		'SELECT passkeys.id, users.email, passkeys.public_key, passkeys.sign_count, passkeys.user_handle FROM passkeys JOIN users ON users.id = passkeys.user_id WHERE passkeys.credential_id=?',
		(bytes_to_base64url(credential.raw_id), ))
	row = c.fetchone()
	if row is None:
		return None, None, "This passkey isn't valid on this box any more."
	passkey_id, email, public_key, sign_count, user_handle = row

	# The passkey must say it's for the user it was added for. (Without a list of
	# credentials in the options, authenticators always say whose passkey it is.)
	if credential.response.user_handle is None or \
			bytes_to_base64url(credential.response.user_handle) != user_handle:
		return None, None, "This passkey isn't valid on this box any more."

	try:
		# This checks the signature, the hostname, that the authenticator verified the user
		# (fingerprint, face, PIN), and that the signature counter went up: a counter that
		# doesn't may be a copied security key. (Passkeys synced between devices always
		# send 0.)
		verified = verify_authentication_response(
			credential=credential,
			expected_challenge=state["challenge"],
			expected_rp_id=get_rp_id(env),
			expected_origin=get_origin(env),
			credential_public_key=base64url_to_bytes(public_key),
			credential_current_sign_count=sign_count,
			require_user_verification=True,
		)
	except Exception as e:
		log.warning("Passkey %d of %s refused: %s", passkey_id, email, one_line(e))
		return None, None, "The passkey couldn't be verified."

	c.execute('UPDATE passkeys SET sign_count=?, last_used=? WHERE id=?',
			(verified.new_sign_count, now(), passkey_id))
	conn.commit()
	return email, passkey_id, None


def one_line(e):
	# An exception's message for the log, on one line (it may repeat what the browser sent).
	return str(e).replace("\r", " ").replace("\n", " ")[:300]

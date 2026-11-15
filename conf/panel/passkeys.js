/*
 * Enhanced Mail-in-a-Box control panel: passkeys (WebAuthn). No dependencies.
 *
 * The box sends the options for navigator.credentials.create() and .get() as JSON, with
 * the binary values (challenge, user id, credential ids) in base64url. These functions
 * turn them into what the browser expects, and the browser's answer back into JSON (the
 * form of PublicKeyCredential.toJSON(), which not every browser has yet) for the box to
 * check. They return promises.
 *
 * - passkeys.supported(): whether this browser can use passkeys here.
 * - passkeys.create(options): adds a passkey (registration).
 * - passkeys.get(options): uses one (login).
 * - passkeys.error_message(error, hostname): what to tell the user when the browser says
 *   no, or null when there is nothing to say (the user canceled).
 */
(function () {
	"use strict";

	function to_buffer(base64url) {
		var base64 = String(base64url).replace(/-/g, "+").replace(/_/g, "/");
		base64 += "===".slice((base64.length + 3) % 4);
		var binary = atob(base64);
		var bytes = new Uint8Array(binary.length);
		for (var i = 0; i < binary.length; i++)
			bytes[i] = binary.charCodeAt(i);
		return bytes.buffer;
	}

	function to_base64url(buffer) {
		if (!buffer)
			return null;
		var bytes = new Uint8Array(buffer);
		var binary = "";
		for (var i = 0; i < bytes.length; i++)
			binary += String.fromCharCode(bytes[i]);
		return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
	}

	function descriptors(list) {
		return (list || []).map(function (c) {
			var d = { type: c.type, id: to_buffer(c.id) };
			if (c.transports)
				d.transports = c.transports;
			return d;
		});
	}

	function supported() {
		return !!(window.isSecureContext && window.PublicKeyCredential && navigator.credentials
			&& navigator.credentials.create && navigator.credentials.get);
	}

	function create(options) {
		var publicKey = {
			rp: options.rp,
			user: {
				id: to_buffer(options.user.id),
				name: options.user.name,
				displayName: options.user.displayName
			},
			challenge: to_buffer(options.challenge),
			pubKeyCredParams: options.pubKeyCredParams,
			timeout: options.timeout,
			excludeCredentials: descriptors(options.excludeCredentials),
			authenticatorSelection: options.authenticatorSelection,
			attestation: options.attestation
		};
		return navigator.credentials.create({ publicKey: publicKey }).then(function (credential) {
			var response = credential.response;
			return {
				id: credential.id,
				rawId: to_base64url(credential.rawId),
				type: credential.type,
				response: {
					clientDataJSON: to_base64url(response.clientDataJSON),
					attestationObject: to_base64url(response.attestationObject),
					transports: response.getTransports ? response.getTransports() : []
				},
				authenticatorAttachment: credential.authenticatorAttachment || null,
				clientExtensionResults: {}
			};
		});
	}

	function get(options) {
		var publicKey = {
			challenge: to_buffer(options.challenge),
			timeout: options.timeout,
			rpId: options.rpId,
			allowCredentials: descriptors(options.allowCredentials),
			userVerification: options.userVerification
		};
		return navigator.credentials.get({ publicKey: publicKey }).then(function (credential) {
			var response = credential.response;
			return {
				id: credential.id,
				rawId: to_base64url(credential.rawId),
				type: credential.type,
				response: {
					clientDataJSON: to_base64url(response.clientDataJSON),
					authenticatorData: to_base64url(response.authenticatorData),
					signature: to_base64url(response.signature),
					userHandle: to_base64url(response.userHandle)
				},
				authenticatorAttachment: credential.authenticatorAttachment || null,
				clientExtensionResults: {}
			};
		});
	}

	function error_message(error, hostname) {
		switch (error && error.name) {
			case "NotAllowedError":
			case "AbortError":
				// Canceled, timed out, or no passkey for this box: the browser said so.
				return null;
			case "InvalidStateError":
				return "This device already has a passkey for your account.";
			case "SecurityError":
				return "Passkeys only work at https://" + hostname + "/admin, with a valid certificate.";
			case "NotSupportedError":
				return "This browser or device can't create a passkey that the box accepts.";
		}
		return "The browser couldn't use a passkey" + (error && error.message ? ": " + error.message : ".");
	}

	window.passkeys = {
		supported: supported,
		create: create,
		get: get,
		error_message: error_message
	};
})();

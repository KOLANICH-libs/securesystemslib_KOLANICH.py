import binascii

from securesystemslib import formats, settings
from securesystemslib.keys import _get_keyid


__license__ = "MIT"


def format_ed25519_dict(public: bytes, private: bytes, scheme="ed25519"):
	"""
	<Purpose>
	  Formats a ed25519 private key dict.

	<Arguments>
	  public:
		Bytes of public key.

	  private:
		Bytes of private key.

	  scheme:
		The signature scheme used by the generated Ed25519 key.

	<Exceptions>
	  None.

	<Side Effects>
	  None.

	<Returns>
	  A dictionary containing the ED25519 keys and other identifying information.
	  Conforms to 'securesystemslib.formats.ED25519KEY_SCHEMA'.
	"""

	assert private is None or len(private) == 32  # nosec assert_used
	assert len(public) == 32  # nosec assert_used

	# Are the arguments properly formatted?  If not, raise an
	# 'securesystemslib.exceptions.FormatError' exceptions.
	formats.ED25519_SIG_SCHEMA.check_match(scheme)

	# Begin building the Ed25519 key dictionary.
	ed25519_key = {}
	keytype = "ed25519"

	# Generate the keyid of the Ed25519 key.  'key_value' corresponds to the
	# 'keyval' entry of the 'Ed25519KEY_SCHEMA' dictionary.  The private key
	# information is not included in the generation of the 'keyid' identifier.
	key_value = {"public": binascii.hexlify(public).decode(), "private": ""}
	keyid = _get_keyid(keytype, scheme, key_value)

	if private is not None:
		# Build the 'ed25519_key' dictionary.  Update 'key_value' with the Ed25519
		# private key prior to adding 'key_value' to 'ed25519_key'.
		key_value["private"] = binascii.hexlify(private).decode()

	ed25519_key["keytype"] = keytype
	ed25519_key["scheme"] = scheme
	ed25519_key["keyid"] = keyid
	ed25519_key["keyid_hash_algorithms"] = settings.HASH_ALGORITHMS
	ed25519_key["keyval"] = key_value

	return ed25519_key

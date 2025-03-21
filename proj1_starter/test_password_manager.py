from json.decoder import JSONDecodeError
import pytest

from password_manager import Keychain
from util import decode_bytes, json_str_to_dict


PASSWORD = "password123!"  # note: this isn't a good password!
KVS = {
    "service1": "pwd1",
    "service2": "pwd2",
    "service3": "pwd3"
}

class TestFunctionality:
    def test_init_without_error(self):
        Keychain.new(PASSWORD)

    def test_set_and_retrieve_password(self):
        keychain = Keychain.new(PASSWORD)
        url = "www.stanford.edu"
        pw = "sunetpassword"
        keychain.set(url, pw)
        assert keychain.get(url) == pw, \
            "Retrieved password not equal to set password"

    def test_set_and_retrieve_multiple_passwords(self):
        keychain = Keychain.new(PASSWORD)
        for key, val in KVS.items():
            keychain.set(key, val)
        for key, val in KVS.items():
            assert keychain.get(key) == val, \
                "Retrieved password not equal to set password"
        
    def test_get_returns_none_for_non_existent_password(self):
        keychain = Keychain.new(PASSWORD)
        for key, val in KVS.items():
            keychain.set(key, val)
        assert keychain.get("www.stanford.edu") is None, \
            "Keychain.get did not return None for non-existent domain"
    
    def test_can_remove_password(self):
        keychain = Keychain.new(PASSWORD)
        for key, val in KVS.items():
            keychain.set(key, val)
        
        assert keychain.get("service1") == KVS["service1"], \
            "Retrieved password not equal to set password"
        assert keychain.remove("service1"), \
            "Keychain.remove did not return True for valid removal"
        assert keychain.get("service1") is None, \
            "Keychain.get did not return None for non-existent domain"
    
    def test_remove_returns_false_if_no_password_for_name(self):
        keychain = Keychain.new(PASSWORD)
        for key, val in KVS.items():
            keychain.set(key, val)
        assert not keychain.remove("www.stanford.edu"), \
            "Removing non-existing domain should return False"
    
    def test_dump_and_restore_database(self):
        keychain = Keychain.new(PASSWORD)
        for key, val in KVS.items():
            keychain.set(key, val)
        
        contents, checksum = keychain.dump()
        new_keychain = Keychain.load(PASSWORD, contents, checksum)

        try:
            json_str_to_dict(contents)
        except JSONDecodeError:
            raise ValueError("Keychain.dump returned invalid JSON")
        
        for key, val in KVS.items():
            assert new_keychain.get(key) == val, \
                "Retrieved password not equal to set password"
    
    def test_fails_to_restore_database_with_incorrect_checksum(self):
        keychain = Keychain.new(PASSWORD)
        for key, val in KVS.items():
            keychain.set(key, val)
        
        contents, _ = keychain.dump()
        checksum = decode_bytes("3GB6WSm+j+jl8pm4Vo9b9CkO2tZJzChu34VeitrwxXM=")

        with pytest.raises(ValueError):
            Keychain.load(PASSWORD, contents, checksum)

    def test_fails_to_restore_database_with_incorrect_password(self):
        keychain = Keychain.new(PASSWORD)
        for key, val in KVS.items():
            keychain.set(key, val)
        
        contents, checksum = keychain.dump()

        with pytest.raises(ValueError):
            Keychain.load("wrong_password", contents, checksum)


class TestSecurity:
    def test_does_not_store_names_and_pwds_in_plain_text(self):
        keychain = Keychain.new(PASSWORD)
        for key, val in KVS.items():
            keychain.set(key, val)
        
        contents, _ = keychain.dump()

        assert PASSWORD not in contents, \
            "Plaintext keychain password is visible in Keychain dump"
        for key, val in KVS.items():
            assert key not in contents, \
                "Plaintext domain is visible in Keychain dump"
            assert val not in contents, \
                "Plaintext password is visible in Keychain dump"
    

class TestAutogradability:
    def test_includes_kvs_object_in_dump(self):
        keychain = Keychain.new(PASSWORD)
        for key, val in KVS.items():
            keychain.set(key, val)
        
        contents, _ = keychain.dump()
        contents_dict = json_str_to_dict(contents)
        assert 'kvs' in contents_dict, \
            "The JSON object returned by Keychain.dump does not contain a 'kvs' key"
        assert isinstance(contents_dict['kvs'], dict), \
            "The 'kvs' attribute of the JSON object returned by Keychain.dump must be a dict"
        assert len(contents_dict['kvs']) == len(KVS), \
            "The KVS in the JSON object returned by Keychain.dump does not contain the \
                correct number of domain/password pairs"
        
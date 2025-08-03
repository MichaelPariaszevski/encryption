from encryption import Encryption

encrypt = Encryption()

recipient_public_key =  "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkE497izArDym3Mzc5cCG\nQzPnpTb0IwfYQL4AjHmGW5ywT6HWI9YM3yOq1jtmCWzs8MRI3mxKAidHaSUCLtDs\naOvd3BuaRZz03TX+Hzt8JvlXFdm+NKHLgdeyrb0dKm9BtlIJpJkN9wqiiwq5nRyQ\n0zEgq6rJe5M/TP/eEjvFmjj/Gi9yTZWCOjMs14AooO+FIFCTzfYKV+hUfjiw95er\nfIlvkMqZpZnDgnWo2Z9GVpQ5UP1Klku/ruUP6tnpY3BwmT+LbpZi730YSCkm3jFa\nAi7Ex+eH29H3qxalaAdyOxAxsFPsnTlWemkmKI8m8YoocB8uo+L40oEvcRwS2xC2\n6wIDAQAB\n-----END PUBLIC KEY-----\n"

encrypted_message, encrypted_symmetric_key = encrypt.send_message(
    "Hello, this is a test message.",
    recipient_public_key
)
from security_checks import full_scan

result = full_scan("http://malware.testing.google.test/testing/malware/")
print(result)

result2 = full_scan("https://bit.ly/somelink")
print(result2)
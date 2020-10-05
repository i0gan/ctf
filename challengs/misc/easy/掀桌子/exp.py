s = 'c8e9aca0c6f2e5f3e8c4efe7a1a0d4e8e5a0e6ece1e7a0e9f3baa0e8eafae3f9e4eafae2eae4e3eaebfaebe3f5e7e9f3e4e3e8eaf9eaf3e2e4e6f2'

i = 0
r = ''
for _ in range(int(len(s) / 2)):
	n  = int(s[i + 0], 16) * 0x10
	n += int(s[i + 1], 16)
	n -= 128
	r += chr(n)
	i += 2
print(r)

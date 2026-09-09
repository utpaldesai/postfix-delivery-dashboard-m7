from pathlib import Path

wrapper = Path("amavisd-release-wrapper.py").read_text()

assert 'result = subprocess.run(["perl", "-T", str(TARGET), *sys.argv[1:]], check=False)' in wrapper
assert 'result = subprocess.run(["perl", str(TARGET), *sys.argv[1:]], check=False)' not in wrapper

print("Milestone 1 amavisd-release Perl taint regression test passed")

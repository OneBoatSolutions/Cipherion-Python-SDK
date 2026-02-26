# 1. Install build tools
python -m pip install --upgrade build twine

# 2. Register at https://pypi.org and generate an API token
#    (Account Settings → API tokens → Add token)

# 3. Store your token
#    Create ~/.pypirc:
[distutils]
index-servers = pypi

[pypi]
username = __token__
password = pypi-AgEIcH...yourtoken...

# 4. Build the distribution archives
cd cipherion-python-sdk
python -m build
# Creates dist/cipherion-0.1.0.tar.gz and dist/cipherion-0.1.0-py3-none-any.whl

# 5. (Optional) Test on TestPyPI first
twine upload --repository testpypi dist/*
pip install --index-url https://test.pypi.org/simple/ cipherion

# 6. Upload to real PyPI
twine upload dist/*

# 7. Verify install
pip install cipherion
python -c "from cipherion import CipherionClient; print('ok')"
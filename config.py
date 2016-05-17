import os

SECRET_KEY = 'p4ssw0rd_c0d3'
SECURITY_PASSWORD_SALT = 'my_s3cUr3_s4lt'
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///db.sqlite')

# # mail settings
# MAIL_SERVER = 'smtp.xxxx.com'
# MAIL_PORT = 465
# MAIL_USE_TLS = False
# MAIL_USE_SSL = True

# MAIL_USERNAME = 'xxxxxxxxxxxx@xxxx.com'
# MAIL_PASSWORD = 'xxxxxxxxxxxxxxxxxxx'

# # mail accounts
# MAIL_DEFAULT_SENDER = 'xxxx@xxxx.com'


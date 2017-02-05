#!/usr/bin/python
#
# Fernando Membrive
#
# Checks if the files in a directory, with a certain filename pattern,
# exceed a given size.
#

import os
import fnmatch
import smtplib

# E-mail notifications configuration
EMAIL_USERNAME = "user@domain.com"
EMAIL_PASSWORD = ""
EMAIL_SMTP = "smtp.domain.com"
EMAIL_PORT = 587
EMAIL_RECIPIENT = "user@domain.com"
EMAIL_SUBJECT = "E-mail subject"

# Check configuration
DIRECTORY = "/foo/bar"
FILENAME_PATTERN = "*.txt"
MAX_FILESIZE = 0

files = []

for file in os.listdir(DIRECTORY):
    if fnmatch.fnmatch(file, FILENAME_PATTERN):
        filestat = os.stat(DIRECTORY+file)
        if filestat.st_size > MAX_FILESIZE:
            print ("The size of " + DIRECTORY + file +
                   " is greater than " + str(MAX_FILESIZE) + ".")
            files.append(file)

if len(files) == 0:
    print "Nothing detected."
    exit()

# Email sending
print "Sending an email with the results to " + EMAIL_RECIPIENT

session = smtplib.SMTP(EMAIL_SMTP, EMAIL_PORT)
session.ehlo()
session.starttls()
session.login(EMAIL_USERNAME, EMAIL_PASSWORD)

headers = "\r\n".join(["from: " + EMAIL_USERNAME,
          "subject: " + EMAIL_SUBJECT,
          "to: " + EMAIL_RECIPIENT,
          "mime-version: 1.0",
          "content-type: text/html"])

content = headers + ("\r\n\r\n The following files at " + DIRECTORY +
                     " has a filesize greater than " + str(MAX_FILESIZE) +
                     ": " + "<br><br>- %s" % "<br>- ".join(map(str, files)))

session.sendmail(EMAIL_USERNAME, EMAIL_RECIPIENT, content)

print "Email successfully sent to " + EMAIL_RECIPIENT

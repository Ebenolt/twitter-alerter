#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from configparser import ConfigParser

parser = ConfigParser()
parser.read('config.ini')

print("Detected configuration:")

if parser.has_section("Twitter-API"):
    print("  Twitter: ")
    if parser.has_option("Twitter-API", "key"):
        print("   -key: "+parser.get("Twitter-API", "key"))
    else:
        print("   /!\\ Missing key /!\\")

    if parser.has_option("Twitter-API", "secret"):
        print("   -secret: "+parser.get("Twitter-API", "secret"))
    else:
        print("   /!\\ Missing secret /!\\")

    if parser.has_option("Twitter-API", "access_token"):
        print("   -access_token: "+parser.get("Twitter-API", "access_token"))
    else:
        print("   /!\\ Missing access_token /!\\")
    
    if parser.has_option("Twitter-API", "access_token_secret"):
        print("   -access_token_secret: "+parser.get("Twitter-API", "access_token_secret"))
    else:
        print("   /!\\ Missing access_token_secret /!\\")
else:
    print("  /!\\ No Twitter section /!\\")

print("")
if parser.has_section("Free-API"):
    print("  Free: ")
    if parser.has_option("Free-API", "username"):
        print("   -username: "+parser.get("Free-API", "username"))
    else:
        print("   /!\\ Missing username /!\\")

    if parser.has_option("Free-API", "pass"):
        print("   -pass: "+parser.get("Free-API", "pass"))
    else:
        print("   /!\\ Missing pass /!\\")

else:
    print("  /!\\ No Free section /!\\")

print("")

if parser.has_section("App"):
    print("  App: ")
    if parser.has_option("App", "logfile"):
        print("   -logfile: "+parser.get("App", "logfile"))
    else:
        print("   /!\\ Missing logfile /!\\")

    if parser.has_option("App", "alert_regex"):
        print("   -alert_regex: "+parser.get("App", "alert_regex"))
    else:
        print("   /!\\ Missing alert_regex /!\\")

    if parser.has_option("App", "banned_regex"):
        print("   -banned_regex: "+parser.get("App", "banned_regex"))
    else:
        print("   /!\\ Missing banned_regex /!\\")
else:
    print("  /!\\ No App section /!\\")

print("")


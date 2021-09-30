#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests, datetime, re, ast, twitter, unidecode, urllib3, os, telebot
from configparser import ConfigParser
from telethon.sync import TelegramClient
from telethon import TelegramClient, sync, events
from telethon.tl.functions.messages import SendMessageRequest
from telethon.tl.types import InputPeerUser
from telethon.tl import types, functions


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = ConfigParser()
parser.read('config.ini')

#Twitter
twitter_key = parser.get("Twitter-API", "key")
twitter_secret = parser.get("Twitter-API", "secret")
twitter_token = parser.get("Twitter-API", "access_token")
twitter_token_secret = parser.get("Twitter-API", "access_token_secret")

#Telegram
tele_api_id=parser.get("Telegram-API", "api_id")
tele_api_hash=parser.get("Telegram-API", "api_hash")
tele_api_token=parser.get("Telegram-API", "token")
tele_phone=parser.get("Telegram-API", "phone")

#Free
free_username = parser.get("Free-API", "username")
free_pass = parser.get("Free-API", "pass")

#App
app_logfile = parser.get("App", "logfile")
app_historyfile = parser.get("App", "historyfile")
app_alert_regex = ast.literal_eval(parser.get("App", "alert_regex"))
app_banned_regex = ast.literal_eval(parser.get("App", "banned_regex"))
app_account = parser.get("App", "account")
app_scrape_amount = parser.get("App", "scrape_amount")
app_alerted_users = ast.literal_eval(parser.get("App", "alerted_users"))


if (not(os.path.isfile(app_logfile))):
    f = open(app_logfile, "a+", encoding="utf-8")
    f.close()

if (not(os.path.isfile(app_historyfile))):
    f = open(app_historyfile, "a+", encoding="utf-8")
    f.close()


def log(text, logfile=app_logfile):
    now = datetime.datetime.now()
    current_time = now.strftime("%d/%m/%Y - %H:%M:%S")
    log_data = "["+current_time+"] "+str(text)
    f = open(logfile, "a+", encoding="utf-8")
    f.write(log_data+"\n")
    f.close()
    print(log_data)

status_dict = {200: "SMS sent",
                400: "Missing parameter",
                402: "Too many SMS",
                403: "Service unavailable or bad login",
                500: "Server error"}

tw_api = twitter.Api(consumer_key=twitter_key,
                    consumer_secret=twitter_secret,
                    access_token_key=twitter_token,
                    access_token_secret=twitter_token_secret)

tele_bot = TelegramClient('session', tele_api_id, tele_api_hash)


def historize(id, historyfile=app_historyfile):
    f = open(historyfile, "a+", encoding="utf-8")
    f.write(str(id)+"\n")
    f.close()

def in_history(id, historyfile=app_historyfile):
    f = open(historyfile, "r", encoding="utf-8")
    lines = f.readlines()
    for line in lines:
        line = line[:-1]
        if line == str(id):
            return True
    f.close()
    return False


def send_sms(message, sms_username=free_username, sms_password=free_pass):
    message = unidecode.unidecode(message)
    r = requests.post('https://smsapi.free-mobile.fr/sendmsg',
                        verify=False,
                        json={'user': sms_username,
                                'pass': sms_password,
                                'msg':message})
    return r.status_code

def send_telegram(user, message):
    try:
        peer = tele_bot.get_input_entity(user)
        receiver = InputPeerUser(peer.user_id, peer.access_hash)
        tele_bot.send_message(receiver, message, parse_mode='html')
        return "OK"
    except Exception as e:
        return e

def does_match_regex(text, dict=app_alert_regex):
    for element in dict:
        if re.match(element, text):
            return True
    return False


def tweet_to_text(tweet):
    result = "New tweet from "+app_account+" !! ["+str(tweet.id)+"] \n\n"
    result += tweet.text+"\n\n"
    result += "Available at: https://twitter.com/"+app_account+"/status/"+str(tweet.id)
    return result

tele_bot.connect()

if not tele_bot.is_user_authorized():
    tele_bot.send_code_request(tele_phone)
    tele_bot.sign_in(tele_phone, input('Enter the code received on '+tele_phone+' : '))


timeline = tw_api.GetUserTimeline(screen_name=app_account, count=app_scrape_amount)
for tweet in timeline:
    if does_match_regex(tweet.text) and not(does_match_regex(tweet.text, app_banned_regex)):
        if in_history(tweet.id) == False:
            historize(str(tweet.id))
            sms_result = send_sms(tweet_to_text(tweet))
            telegram_result = "Telegram message sent to: "
            for user in app_alerted_users:
                res = send_telegram(user, tweet_to_text(tweet))
                if res == "OK":
                    telegram_result += user+", "
            log("Sending https://twitter.com/"+app_account+"/status/"+str(tweet.id)+"\n   - "+status_dict[sms_result]+"\n   - "+telegram_result)

tele_bot.disconnect()


# https://python-twitter.readthedocs.io/en/latest/getting_started.html

# https://www.geeksforgeeks.org/send-message-to-telegram-user-using-python/
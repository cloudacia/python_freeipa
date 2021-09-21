import urllib3
import json
import pandas as pd
import warnings
import os
import subprocess
from datetime import date
from python_freeipa import ClientMeta
from itertools import chain

server = ''
username = ''
password = ''
group = ''
date = date.today()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.simplefilter(action='ignore', category=FutureWarning)


def connect_to_ldap(server, username, password):
    """ connect to the LDAP server (FreeIPA) """
    server = server
    username = username
    password = password
    client = ClientMeta('ipa-server-1.ops.iad1.ccmteam.com', verify_ssl=False)
    client.login(username, password)
    return client


def get_user_list(client, group):
    """ Get the list of usernames under a group (by default slc1vpn group) """
    conn = client
    group = group
    response = conn.group_find(a_criteria=group)
    members = response['result'][0]['member_user']
    return members


def get_user_info(client, user):
    """ Get the profile of an user"""
    client = client
    response = client.user_find(o_uid=user)
    return response


def create_user_matrix(client, user_list):
    """ Get the profile of all users under an specific group """
    client = client
    user_list = user_list
    user_data_list = []
    for user in user_list:
        data = get_user_info(client, user)
        data = data['result']
        user_data_list.append(data)

    df = pd.DataFrame(list(chain.from_iterable(user_data_list)))
    return df


def clean_dataframe(df):
    """ Clean data return from the server. The data return is JSON format
    but, is not ready to used to build a report."""

    drop_cols = ['krblastfailedauth','krblastpwdchange', \
    'krblastadminunlock','preserved', 'krbcanonicalname', 'displayname',  \
    'nsaccountlock', 'krbticketflags', 'sshpubkeyfp', 'memberof_group',  \
    'ipasshpubkey', 'krbextradata', 'dn', 'mepmanagedentry', \
    'krbprincipalname', 'objectclass', 'gecos', 'initials', \
    'krbpasswordexpiration', 'krbpwdpolicyreference']

    df = df.drop(drop_cols, axis=1)
    new_cols ={'cn':'name', 'homedirectory':'home_directory'}
    df = df.rename(columns=new_cols)
    df_copy = df.copy()

    df_copy['name'] = df_copy['name'].astype(str)
    df_copy['name'] = df_copy['name'].str.replace('[', ' ')
    df_copy['name'] = df_copy['name'].str.replace(']', ' ')
    df_copy['name'] = df_copy['name'].str.replace("'", ' ')
    df_copy['name'] = df_copy['name'].str.strip()

    df_copy['mail'] = df_copy['mail'].astype(str)
    df_copy['mail'] = df_copy['mail'].str.replace('[', ' ')
    df_copy['mail'] = df_copy['mail'].str.replace(']', ' ')
    df_copy['mail'] = df_copy['mail'].str.replace("'", ' ')
    df_copy['mail'] = df_copy['mail'].str.lower()

    df_copy['home_directory'] = df_copy['home_directory'].astype(str)
    df_copy['home_directory'] = df_copy['home_directory'].str.replace('[', ' ')
    df_copy['home_directory'] = df_copy['home_directory'].str.replace(']', ' ')
    df_copy['home_directory'] = df_copy['home_directory'].str.replace("'", ' ')

    df_copy['uid'] = df_copy['uid'].astype(str)
    df_copy['uid'] = df_copy['uid'].str.replace('[', ' ')
    df_copy['uid'] = df_copy['uid'].str.replace(']', ' ')
    df_copy['uid'] = df_copy['uid'].str.replace("'", ' ')

    df_copy['loginshell'] = df_copy['loginshell'].astype(str)
    df_copy['loginshell'] = df_copy['loginshell'].str.replace('[', ' ')
    df_copy['loginshell'] = df_copy['loginshell'].str.replace(']', ' ')
    df_copy['loginshell'] = df_copy['loginshell'].str.replace("'", ' ')

    df_copy['uidnumber'] = df_copy['uidnumber'].astype(str)
    df_copy['uidnumber'] = df_copy['uidnumber'].str.replace('[', ' ')
    df_copy['uidnumber'] = df_copy['uidnumber'].str.replace(']', ' ')
    df_copy['uidnumber'] = df_copy['uidnumber'].str.replace("'", ' ')

    df_copy['mail'] = df_copy['mail'].astype(str)
    df_copy['mail'] = df_copy['mail'].str.replace('[', ' ')
    df_copy['mail'] = df_copy['mail'].str.replace(']', ' ')
    df_copy['mail'] = df_copy['mail'].str.replace("'", ' ')

    df_copy['ipauniqueid'] = df_copy['ipauniqueid'].astype(str)
    df_copy['ipauniqueid'] = df_copy['ipauniqueid'].str.replace('[', ' ')
    df_copy['ipauniqueid'] = df_copy['ipauniqueid'].str.replace(']', ' ')
    df_copy['ipauniqueid'] = df_copy['ipauniqueid'].str.replace("'", ' ')

    df_copy = df_copy.rename({'memberof_sudorule':'memberof_sudo_rule', \
                            'loginshell':'login_shell', 'uidnumber':'uid_number', \
                            'mail':'email', 'memberof_hbacrule':'memberof_hbac_rule', \
                            'ipauniqueid':'ipa_unique_id', 'gidnumber':'gid_number', \
                            'krbloginfailedcount':'faile_login_dcount'}, axis=1)

    cols_2_updated = ['name', 'givenname','sn', 'memberof_sudo_rule', \
                    'home_directory', 'uid', 'login_shell', 'uid_number', \
                    'email', 'memberof_hbac_rule', 'ipa_unique_id', \
                    'gid_number', 'faile_login_dcount']

    df_copy = df_copy[cols_2_updated]
    df_copy = df_copy.rename({'name': 'display_name', 'givenname':'first_name',\
                            'sn':'last_name'}, axis=1)

    df_copy['first_name'] = df_copy['first_name'].astype(str)
    df_copy['first_name'] = df_copy['first_name'].str.replace('[', ' ')
    df_copy['first_name'] = df_copy['first_name'].str.replace(']', ' ')
    df_copy['first_name'] = df_copy['first_name'].str.replace("'", ' ')

    df_copy['last_name'] = df_copy['last_name'].astype(str)
    df_copy['last_name'] = df_copy['last_name'].str.replace('[', ' ')
    df_copy['last_name'] = df_copy['last_name'].str.replace(']', ' ')
    df_copy['last_name'] = df_copy['last_name'].str.replace("'", ' ')

    return df_copy


def save_to_csv(df):
    """ Save the data into a CSV file"""
    output = subprocess.run(['pwd'], stdout=subprocess.PIPE)
    output = output.stdout.decode('utf-8')
    output = output.replace('\n', '')
    string = output + '/' + 'vpn_users_report_{0}.csv'.format(date)
    string = string.replace('-', '_')
    os.chdir(output)
    df.to_csv(string)


if __name__ == "__main__":
    conn = connect_to_ldap(server, username, password)
    users = get_user_list(conn, group)
    df = create_user_matrix(conn, users)
    cleaned_df = clean_dataframe(df)
    save_to_csv(cleaned_df)
    print(cleaned_df)

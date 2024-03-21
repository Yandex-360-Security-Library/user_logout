#!/usr/bin/env python3
import argparse
import json
import logging
import sys
import warnings
from dataclasses import dataclass
from http import HTTPStatus
from os import environ
from textwrap import dedent
from typing import Optional, Union

import requests

warnings.filterwarnings("ignore")

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("user logout")

OAUTH_TOKEN_ARG = "OAUTH_TOKEN"
ORGANIZATION_ID_ARG = "ORGANIZATION_ID"
YANDEX_360_DIRECTORY_API_URL = "https://api360.yandex.net/directory/v1/"
YANDEX_360_SECURITY_API_URL = "https://api360.yandex.net/security/v1/"
EXIT_CODE = 1


def arg_parser():
    parser = argparse.ArgumentParser(
        description=dedent(
            f"""
            Performs the user's logout from his Yandex
            360 account using his username in the organization.

            Environment options:
            {OAUTH_TOKEN_ARG} - OAuth Token,
            {ORGANIZATION_ID_ARG} - Organization ID,

            For example:
            {OAUTH_TOKEN_ARG}="AgAAgfAAAAD4beAkEsWrefhNeyN1TVYjGT1k",
            {ORGANIZATION_ID_ARG}=123
            """
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--usernames", help="List of usernames", type=str, nargs="*", required=True
    )

    return parser


def main():
    parser = arg_parser()
    args = parser.parse_args()
    try:
        settings = get_settings()
    except KeyError as key:
        logger.error(f"Required environment vars not provided: {key}")
        parser.print_usage()
        sys.exit(EXIT_CODE)
    if len(args.usernames) == 0:
        logger.error("List of usernames is empty.")
        parser.print_usage()
        sys.exit(EXIT_CODE)
    logger.info("User_logout started.")
    for user in args.usernames:
        try:
            client = API360(oauth_token=settings.oauth_token)
            org_users = client.get_users(settings.organization_id)
            page, last_page = org_users["page"], org_users["pages"]
            user_id = None
            while page <= last_page:
                user_id = get_user(users=org_users["users"], login=user)
                if user_id:
                    break
                page += 1
                org_users = client.get_users(settings.organization_id, page=page)
            if not user_id:
                raise UserNotFoundError(
                    f"User {user} not found in the organization {settings.organization_id}."
                )
            response = client.logout_user(
                org_id=settings.organization_id, user_id=user_id
            )
            if response == b"{}":
                logger.info(f"A logout has been performed for the user {user}")
            else:
                raise Exception
        except UserNotFoundError as err:
            logger.error(err)
    logger.info("User_logout finished.")


def get_settings():
    settings = SettingParams(
        oauth_token=environ[OAUTH_TOKEN_ARG],
        organization_id=environ[ORGANIZATION_ID_ARG],
    )
    return settings


class API360:
    def __init__(self, oauth_token: str):
        self._headers = {"Authorization": f"OAuth {oauth_token}"}

    def get_users(self, org_id: Union[int, str], page: Union[int, str] = 1):
        url = f"{YANDEX_360_DIRECTORY_API_URL}org/{org_id}/users/?page={page}"
        r = requests.get(url=url, headers=self._headers, verify=False)
        if r.status_code != HTTPStatus.OK.value:
            if r.status_code == HTTPStatus.UNAUTHORIZED.value:
                raise ClientError("Invalid OAuth Token")
            elif r.status_code == HTTPStatus.FORBIDDEN.value:
                raise ClientError(
                    "Restriction of access permissions. "
                    f"Check the token permissions in the organization {org_id}"
                )
            elif r.status_code == HTTPStatus.NOT_FOUND.value:
                raise ClientError("Invalid url")
            elif r.status_code == HTTPStatus.INTERNAL_SERVER_ERROR.value:
                raise ClientError("Server-side error. Try later.")
            raise ClientError(f"Unexpected status code: {r.status_code}")
        return json.loads(r.content)

    def logout_user(self, org_id: Union[int, str], user_id: Union[int, str]):
        url = f"{YANDEX_360_SECURITY_API_URL}org/{org_id}/domain_sessions/users/{user_id}/logout"
        r = requests.put(url=url, headers=self._headers, verify=False)
        if r.status_code != HTTPStatus.OK.value:
            raise ClientError(f"Unexpected status code: {r.status_code}")
        return r.content


def get_user(users: list, login: str) -> Optional[str]:
    if "@" in login:
        login = login[: login.rfind("@")]
    for user in users:
        if user["nickname"] == login:
            return user["id"]
        elif login in user["aliases"]:
            return user["id"]
    return None


@dataclass
class SettingParams:
    oauth_token: str
    organization_id: str


class UserLogoutError(Exception):
    pass


class ClientError(UserLogoutError):
    pass


class UserNotFoundError(UserLogoutError):
    pass


if __name__ == "__main__":
    try:
        main()
    except ClientError as err:
        logger.error(err)
        sys.exit(EXIT_CODE)
    except Exception as exp:
        logger.exception(exp)
        sys.exit(EXIT_CODE)

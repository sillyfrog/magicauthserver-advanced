import os
import pathlib

SECRETS_BASE = pathlib.Path("/run/secrets")


def getconf(confname, default=None, raiseerror=False):
    """Tries to get an passed configuration name, returning <default> if not found

    Tries Docker Secrets first, these match the file name of "confname" exactly.
    If this is not present, will try Env variables, these are assumed to be all
    upper case.
    If raiseerror is True, a ValueError error will be raised if the configuration
    has not been explicitly set.
    """
    secrentfn = SECRETS_BASE / confname
    if secrentfn.is_file():
        return secrentfn.open().read()
    if confname.upper() in os.environ:
        return os.environ[confname.upper()]
    if raiseerror:
        raise ValueError("{} not configured".format(confname))
    return default


def getbool(confname, default=False, raiseerror=False):
    """As per getconf, but always enforces returning a Bool"""
    conf = getconf(confname, default=default, raiseerror=raiseerror)
    if type(conf) == str:
        conf = conf.lower()
        if conf == "true":
            return True
    return bool(conf)


def getint(confname, default=None, raiseerror=False):
    """As per getconf, but always enforces returning an Int """
    conf = getconf(confname, default=default, raiseerror=raiseerror)
    return int(conf)

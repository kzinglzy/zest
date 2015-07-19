#!/usr/bin/env python3
# coding:utf-8


# TODO
class BaseExc(Exception):

    """ Base Exception.

    Help to use the doc info as a exception description.
    """

    def __init__(self, exc_info=None):
        super(Exception, self).__init__(exc_info or self.__doc__)


class ImmutableTypeExc(BaseExc):

    """ Immutable Type is read-only.
    """


class ControllerExc(BaseExc):

    """ Invalid route Controller define.

    Controller should have at least one param and it's first params
    will be pass on a `Request` isinstance represents the request context.
    """

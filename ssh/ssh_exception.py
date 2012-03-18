# Copyright (C) 2011  Jeff Forcier <jeff@bitprophet.org>
#
# This file is part of ssh.
#
# 'ssh' is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# 'ssh' is distrubuted in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with 'ssh'; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Suite 500, Boston, MA  02110-1335  USA.

"""
Exceptions defined by ssh.
"""


class SSHException (Exception):
    """
    Exception raised by failures in SSH2 protocol negotiation or logic errors.
    """


class AuthenticationException (SSHException):
    """
    Exception raised when authentication failed for some reason.  It may be
    possible to retry with different credentials.  (Other classes specify more
    specific reasons.)
    
    @since: 1.6
    """
    

class PasswordRequiredException (AuthenticationException):
    """
    Exception raised when a password is needed to unlock a private key file.
    """


class BadAuthenticationType (AuthenticationException):
    """
    Exception raised when an authentication type (like password) is used, but
    the server isn't allowing that type.  (It may only allow public-key, for
    example.)
    
    @ivar allowed_types: list of allowed authentication types provided by the
        server (possible values are: C{"none"}, C{"password"}, and
        C{"publickey"}).
    @type allowed_types: list
    
    @since: 1.1
    """
    allowed_types = []
    
    def __init__(self, explanation, types):
        super(BadAuthenticationType, self).__init__(explanation)
        self.allowed_types = types
     
    def __str__(self):
        return super(BadAuthenticationType, self).__str__() + ' (allowed_types=%r)' % self.allowed_types


class PartialAuthentication (AuthenticationException):
    """
    An internal exception thrown in the case of partial authentication.
    """
    allowed_types = []
    
    def __init__(self, types):
        super(PartialAuthentication, self).__init__('partial authentication')
        self.allowed_types = types


class ChannelException (SSHException):
    """
    Exception raised when an attempt to open a new L{Channel} fails.
    
    @ivar code: the error code returned by the server
    @type code: int
    
    @since: 1.6
    """
    def __init__(self, code, text):
        super(ChannelException, self).__init__(text)
        self.code = code


class BadHostKeyException (SSHException):
    """
    The host key given by the SSH server did not match what we were expecting.
    
    @ivar hostname: the hostname of the SSH server
    @type hostname: str
    @ivar key: the host key presented by the server
    @type key: L{PKey}
    @ivar expected_key: the host key expected
    @type expected_key: L{PKey}
    
    @since: 1.6
    """
    def __init__(self, hostname, got_key, expected_key):
        super(BadHostKeyException, self).__init__('Host key for server %s does not match!' % hostname)
        self.hostname = hostname
        self.key = got_key
        self.expected_key = expected_key


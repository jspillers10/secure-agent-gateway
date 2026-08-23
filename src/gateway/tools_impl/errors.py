class ToolExecutionError(Exception):
    """Raised by a mock tool handler when it cannot fulfil a request.

    Caught at the API boundary and converted into a safe, generic error
    response; the underlying message is logged server-side only and never
    reflected verbatim to the client.
    """

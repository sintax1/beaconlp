from flask.globals import _request_ctx_stack
import json


class FilterBuilderWidget(object):
    """
    Filter Builder Form Widget

    """
    template = '/widgets/filterbuilder.html'
    template_args = None
    beacon_filters = []
    beacon_fields = []

    def __init__(self, **kwargs):
        if 'beacon_filters' not in kwargs:
            kwargs['beacon_filters'] = self.beacon_filters
        if 'beacon_fields' not in kwargs:
            kwargs['beacon_fields'] = self.beacon_fields

        self.template_args = kwargs

    def __call__(self, field, **kwargs):

        kwargs.setdefault('id', field.id)
        kwargs.setdefault('name', field.name)

        if field.data:
            kwargs['filter_rules'] = "rules: %s" % field.data

        ctx = _request_ctx_stack.top
        jinja_env = ctx.app.jinja_env

        template = jinja_env.get_template(self.template)
        args = self.template_args.copy()
        args.update(kwargs)
        return template.render(args)


class BeaconFieldsWidget(object):
    """
    Beacon Fields Form Widget

    """
    template = '/widgets/beaconfields.html'
    template_args = None
    beacon_fields = []
    packet_fields = []

    data_mapping = (
        ('Raw.load', 'type'),
        ('Raw.load', 'uuid'),
        ('Raw.load', 'data_length'),
        ('Raw.load', 'data'),
    )

    def __init__(self, **kwargs):
        if 'beacon_fields' not in kwargs:
            kwargs['beacon_fields'] = self.beacon_fields
        if 'packet_fields' not in kwargs:
            kwargs['packet_fields'] = self.packet_fields
        if 'data_mapping' not in kwargs:
            kwargs['data_mapping'] = self.data_mapping

        self.template_args = kwargs

    def __call__(self, field, **kwargs):
        kwargs.setdefault('id', field.id)
        kwargs.setdefault('name', field.name)
        kwargs.setdefault('data_mapping', self.data_mapping)

        if field.data:
            kwargs['data_mapping'] = json.loads(field.data)

        ctx = _request_ctx_stack.top
        jinja_env = ctx.app.jinja_env

        template = jinja_env.get_template(self.template)
        args = self.template_args.copy()
        args.update(kwargs)
        return template.render(args)

class ResponseFieldsWidget(object):
    """
    Form widget for message response format
    """
    template = '/widgets/responsefields.html'
    template_args = None
    response_types = []
    packet_fields = []
    response_fields = []
    data_mapping = (
        ('', 'type'),
        ('', 'data_length'),
        ('', 'data')
    )

    def __init__(self, **kwargs):
        if 'response_types' not in kwargs:
            kwargs['response_types'] = self.reply_type
        if 'response_fields' not in kwargs:
            kwargs['response_fields'] = self.response_fields
        if 'packet_fields' not in kwargs:
            kwargs['packet_fields'] = self.packet_fields
        if 'data_mapping' not in kwargs:
            kwargs['data_mapping'] = self.data_mapping

        self.template_args = kwargs

    def __call__(self, field, **kwargs):
        kwargs.setdefault('id', field.id)
        kwargs.setdefault('name', field.name)
        kwargs.setdefault('response_types', self.response_types)
        kwargs.setdefault('data_mapping', self.data_mapping)

        ctx = _request_ctx_stack.top
        jinja_env = ctx.app.jinja_env

        template = jinja_env.get_template(self.template)
        args = self.template_args.copy()
        args.update(kwargs)
        return template.render(args)

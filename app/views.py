from flask import (
    render_template, redirect, make_response, request)
from flask.ext.appbuilder.models.sqla.interface import SQLAInterface
from flask.ext.appbuilder import ModelView
from flask.ext.appbuilder.baseviews import expose_api
from flask.ext.appbuilder.actions import action
from app import appbuilder, db
from app.widgets import (
    FilterBuilderWidget, BeaconFieldsWidget, ResponseFieldsWidget)
from wtforms import (
    SelectField, Field, validators)
from flask_appbuilder.fieldwidgets import (
    Select2Widget, Select2ManyWidget)
from .models import (
    Implant, Task, TASK_TYPES, Log, DataStore, Beacon)
from wtforms.ext.sqlalchemy.fields import QuerySelectField
from filters import (
    get_querybuilder_filters_json, get_all_packet_fields)
from messages import (
    get_all_beacon_fields_json, get_all_beacon_fields, 
    json_to_beacon, get_all_task_fields)
from message_responses.responses import get_all_response_types
from flask_appbuilder.security.decorators import (
    has_access_api, permission_name)

from datetime import datetime
from utils import is_ascii

from validators import BeaconDataMappingCheck
import json


def get_assigned_tasks():
    return db.session.query(Task)


class TaskModelView(ModelView):
    datamodel = SQLAInterface(Task)

    add_form_extra_fields = {
        'type': SelectField(
            'Type', choices=TASK_TYPES,
            description=(
                'The type of task so the implant knows how to '
                'handle the Command or Data'),
            widget=Select2Widget())
    }
    edit_form_extra_fields = {
        'type': SelectField(
            'Type', choices=TASK_TYPES,
            description=(
                'The type of task so the implant knows how to '
                'handle the Command or Data'),
            widget=Select2Widget())
    }
    label_columns = {'implant': 'Implant'}
    list_columns = ['id', 'task_type', 'command', 'data']
    show_fieldsets = [
        ('Summary', {'fields': ['task_type']}),
        ('Details', {'fields': ['command', 'data']}),
    ]
    add_columns = ['type', 'command', 'data']
    description_columns = {
        'command': (
            'String of command(s) used by simple '
            'command execution task types'),
        'data': (
            'File used by task types that require a data object (e.g. exe)'),
    }
    edit_columns = ['type', 'command', 'data']


class ImplantModelView(ModelView):
    datamodel = SQLAInterface(Implant)
    base_order = ('last_beacon_received','desc')

    edit_form_extra_fields = {
        'assigned_tasks': QuerySelectField(
            'Tasks', query_factory=get_assigned_tasks,
            description='Assigned Tasks', widget=Select2ManyWidget())}

    label_columns = {'task': 'Task'}
    list_columns = [
        'uuid', 'name', 'external_ip_address', 'internal_ip_address',
        'tasks_assigned', 'last_beacon_received', 'active', 'all_tasks']

    show_fieldsets = [
        ('Summary', {'fields': [
            'uuid', 'name', 'last_beacon_received', 'active']}),
        ('Details', {'fields': [
            'external_ip_address', 'internal_ip_address']}),
        ('Tasking', {'fields': ['tasks']})]

    add_columns = ['uuid', 'name', 'tasks', 'active']
    edit_columns = ['uuid', 'name', 'tasks', 'active']

    description_columns = {
        'uuid': (
            'Unique identifier for this implant.(32 lowercase hexidecimal'
            ' digits in this format: de305d54-75b4-431b-adb2-eb6b9e546014)'),
        'name': 'Human readable identifier for the implant',
        'last_beacon_recevied': (
            'Timestamp of the last beacon received from this implant'),
        'active': 'Enable / Disable tasking this implant',
        'tasks': 'Tasks assigned but not yet processed by this implant'
    }


class DataStoreModelView(ModelView):
    datamodel = SQLAInterface(DataStore)
    base_permissions = ['can_list', 'can_show']
    base_order = ('timestamp','desc')

    label_columns = {'data_type': 'Type'}
    list_columns = ['timestamp', 'data_type', 'data']

    @action("muldelete", "Delete", "Delete all Really?", "fa-trash")
    def muldelete(self, items):
        if isinstance(items, list):
            self.datamodel.delete_all(items)
            self.update_redirect()
        else:
            self.datamodel.delete(items)
        return redirect(self.get_redirect())


class LogModelView(ModelView):
    datamodel = SQLAInterface(Log)
    base_permissions = ['can_list', 'can_show', 'can_post_log']
    base_order = ('timestamp','desc')

    list_columns = ['timestamp', 'message_type', 'message']

    @expose_api(name='post_log', url='/api/postlog', methods=['POST'])
    @has_access_api
    def post_log(self):
        """API used for logging messages from LP to Controller"""
        data = json.loads(request.data)

        log = Log(
            message_type=data['message_type'],
            message=data['message']
        )
        db.session.add(log)
        db.session.commit()

        http_return_code = 200
        response = make_response('Success', http_return_code)
        return response


class BeaconModelView(ModelView):
    datamodel = SQLAInterface(Beacon)
    base_permissions = [
        'can_list', 'can_show', 'can_add', 'can_edit', 'can_post_beacon']

    edit_form_extra_fields = {
        'beacon_filter': Field(
            'Beacon Filter',
            widget=FilterBuilderWidget(
                beacon_filters=get_querybuilder_filters_json(),
                beacon_fields=get_all_beacon_fields_json()),
            validators=[validators.Required()],
            description=(
                'Only incoming Beacon packets matching this '
                'filter will be processed')),
        'beacon_data_mapping': Field(
            'Beacon Data Mapping',
            widget=BeaconFieldsWidget(
                packet_fields=get_all_packet_fields(),
                beacon_fields=get_all_beacon_fields()),
            validators=[validators.Required(), BeaconDataMappingCheck()],
            description=(
                'Extract message data based on the selected '
                'mapping schema')),
        'response_data_mapping': Field(
            'Response Data Mapping',
            widget=ResponseFieldsWidget(
                response_types=get_all_response_types(),
                packet_fields=get_all_packet_fields(),
                response_fields=get_all_task_fields()),
            validators=[validators.Required(), BeaconDataMappingCheck()],
            description=(
                'Format response messages based on the selected '
                'mapping schema'))
    }
    add_form_extra_fields = {
        'beacon_filter': Field(
            'Beacon Filter',
            widget=FilterBuilderWidget(
                beacon_filters=get_querybuilder_filters_json()),
            validators=[validators.Required()],
            description=(
                'Only incoming packets matching this filter will '
                'be processed as a Beacon')),
        'beacon_data_mapping': Field(
            'Beacon Data Mapping',
            widget=BeaconFieldsWidget(
                packet_fields=get_all_packet_fields(),
                beacon_fields=get_all_beacon_fields()),
            validators=[validators.Required(), BeaconDataMappingCheck()],
            description=(
                'Extract message data based on the selected mapping schema')),
        'response_data_mapping': Field(
            'Response Data Mapping',
            widget=ResponseFieldsWidget(
                response_types=get_all_response_types(),
                packet_fields=get_all_packet_fields(),
                response_fields=get_all_task_fields()),
            validators=[validators.Required(), BeaconDataMappingCheck()],
            description=(
                'Format reply messages based on the selected mapping schema'))
    }
    edit_columns = [
        'name', 'beacon_filter', 'beacon_data_mapping',
        'response_data_mapping']
    add_columns = [
        'name', 'beacon_filter', 'beacon_data_mapping',
        'response_data_mapping']
    list_columns = [
        'name', 'beacon_filter', 'beacon_data_mapping',
        'response_data_mapping']

    show_fieldsets = [
        ('Filter', {'fields': ['name', 'beacon_filter']}),
        ('Beacon Data Mapping', {'fields': ['beacon_data_mapping']}),
        ('Task Data Mapping', {
            'fields': ['response_data_mapping']})]

    description_columns = {
        'name': 'Simple name for easy reference'
    }

    @expose_api(name='post_beacon', url='/api/postbeacon', methods=['POST'])
    @has_access_api
    def post_beacon(self):
        """API used to send captured beacons from LP to Controller"""

        beacon = json_to_beacon(request.data)

        # Check if implant already exists
        implant = db.session.query(Implant).filter_by(
            uuid=beacon['uuid']).first()

        if implant:
            # Update existing implant
            implant.last_beacon_received = datetime.now()
            implant.external_ip_address = beacon['external_ip_address']
            db.session.commit()
        else:
            # Add new implant
            implant = Implant(uuid=beacon['uuid'])
            db.session.add(implant)
            db.session.commit()

        # Store beacon data
        if 'data' in beacon:
            beacon_data = beacon['data']
            if beacon_data:

                datastore = DataStore(
                    implant=[implant], timestamp=datetime.now())

                if is_ascii(beacon_data):
                    datastore.text_received = beacon_data
                else:
                    datastore.data_received = beacon_data

                db.session.add(datastore)
                db.session.commit()

        http_return_code = 200
        response = make_response('Success', http_return_code)
        return response


@appbuilder.app.errorhandler(404)
def page_not_found(e):
    """
        Application wide 404 error handler
    """
    return render_template(
        '404.html', base_template=appbuilder.base_template,
        appbuilder=appbuilder), 404

db.create_all()

appbuilder.add_view(
    ImplantModelView, "List Implants", icon="fa-laptop",
    category="Implants", category_icon="fa-laptop")
appbuilder.add_view(
    TaskModelView, "List Tasks", icon="fa-tasks", category="Tasks",
    category_icon="fa-tasks")

appbuilder.add_view(
    DataStoreModelView, "Show Data Store", icon="fa-usd",
    category="Data Store", category_icon="fa-usd")
appbuilder.add_view(
    LogModelView, "Show Log", icon="fa-file-text-o", category="Log",
    category_icon="fa-file-text-o")
appbuilder.add_view(
    BeaconModelView, "List Beacon", icon="fa-filter", category="Beacons",
    category_icon="fa-filter")

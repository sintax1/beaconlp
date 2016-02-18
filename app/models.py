from flask import Markup
from flask.ext.appbuilder import Model
from flask.ext.appbuilder.models.mixins import FileColumn
from flask.ext.appbuilder.models.decorators import renders
from sqlalchemy import (
    Column, Integer, String, ForeignKey, Boolean, DateTime, Table)
from sqlalchemy.orm import relationship

import datetime

#TODO: Remove this
import sys
sys.path.append('/root')
#

from utils import generate_uuid

TASK_TYPES = (
    ('0', 'CLI Command'),
    ('1', 'Python Commands'),
    ('2', 'Binary Upload & Execute'),
)

assoc_tasks_implant = Table(
    'tasks_implant', Model.metadata,
    Column('id', Integer, primary_key=True),
    Column('task_id', Integer, ForeignKey('task.id')),
    Column('implant_id', Integer, ForeignKey('implant.id'))
)

assoc_datastore_implant = Table(
    'datastore_implant', Model.metadata,
    Column('id', Integer, primary_key=True),
    Column('datastore_id', Integer, ForeignKey('data_store.id')),
    Column('implant_id', Integer, ForeignKey('implant.id'))
)


class Implant(Model):
    """Model for implant details

    Attributes:
        id:     unique index of implant in table
        name:   user editable implant name
        uuid:   unique implant id
        active: Enable or disable implant tasking
        tasks:  Tasks queued for each implant
    """

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36), unique=True, default=generate_uuid)

    name = Column(String(80), nullable=True)
    internal_ip_address = Column(String(16), nullable=True)
    external_ip_address = Column(String(16), nullable=True)
    hostname = Column(String(80), nullable=True)

    project = Column(String(80), nullable=True)

    active = Column(Boolean, default=True)
    last_beacon_received = Column(DateTime, nullable=True)

    tasks = relationship(
        'Task', secondary=assoc_tasks_implant, backref='implant')
    datastores = relationship(
        'DataStore', secondary=assoc_datastore_implant, backref='implant')

    def tasks_assigned(self):
        if self.tasks:
            return True

    def all_tasks(self):
        return self.tasks

    def __repr__(self):
        return '%s : %s : %s' % (self.uuid, self.name, self.hostname)


class Task(Model):
    """Model for implant task

    Attributes:
        id:     uniqe index of task in table
        type:   Type of task
                    %s
        data:   The task data (commands, binary, etc)
    """ % ("\n".join(task) for task in TASK_TYPES)

    id = Column(Integer, primary_key=True)
    type = Column(Integer)
    data = Column(FileColumn, nullable=True)
    command = Column(String(400), nullable=True)

    @renders('type')
    def task_type(self):
        return Markup(TASK_TYPES[self.type][1])

    def __repr__(self):
        return '%r : %r' % (str(TASK_TYPES[self.type][1]), str(self.command))


class Log(Model):
    """Model for logging implant actions"""
    id = Column(Integer, primary_key=True)
    type = Column(String(12))  # Error, Warning, Info
    timestamp = Column(DateTime, onupdate=datetime.datetime.now)
    implant_uuid = Column(String(36))
    implant_name = Column(String(80), nullable=True)
    task_id = Column(Integer)
    task_type = Column(Integer)
    task_command = Column(String(400), nullable=True)
    task_data = Column(FileColumn, nullable=True)


class DataStore(Model):
    """Model for storing implant collected data"""
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, onupdate=datetime.datetime.now)

    text_received = Column(String(600), nullable=True)
    data_received = Column(FileColumn, nullable=True)


class Beacon(Model):
    """Model for storing user created beacon filters"""
    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    beacon_filter = Column(String(600), nullable=False)
    beacon_data_mapping = Column(String(600), nullable=False)

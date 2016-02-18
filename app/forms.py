from wtforms import StringField
from wtforms.validators import DataRequired
from flask.ext.appbuilder.fieldwidgets import BS3TextFieldWidget
from flask.ext.appbuilder.forms import DynamicForm
from app.widgets import FilterBuilderWidget


class FilterBuilderForm(DynamicForm):
    name = StringField(
        ('name'),
        description=('Name your filter'),
        validators=[DataRequired()],
        widget=BS3TextFieldWidget()
    )
    filter_rules = StringField(
        ('filter_rules'),
        validators=[DataRequired()],
        widget=FilterBuilderWidget()
    )

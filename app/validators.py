from wtforms.validators import ValidationError
from messages import message_test_data
from utils import test_beacon_data_mapping


class BeaconDataMappingCheck(object):

    """
    Verifies that the Beacon message data mapped to the
    packet fields is compatible
    """
    def __call__(self, form, field):

        #print "Validator data:", field.data

        success, message = test_beacon_data_mapping(
            message_test_data, field.data)

        if not success:
            message = field.gettext('%s' % message)

            raise ValidationError(message)

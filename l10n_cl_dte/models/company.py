# -*- coding: utf-8 -*-
##############################################################################
# For copyright and license notices, see __openerp__.py file in module root
# directory
##############################################################################
from odoo import fields, models, api, _
from odoo.exceptions import UserError
import logging

_logger = logging.getLogger(__name__)

class DteEmail(models.Model):
    """
    Email for DTE stuff
    """
    _inherit = 'res.company'

    dte_email = fields.Char('DTE Email', related='partner_id.dte_email')
    dte_service_provider = fields.Selection([
            ('', 'None'),
            ('FACTURACION', 'facturacion.cl'),
            ('LIBREDTE', 'LibreDTE'),
            ('SIIHOMO', 'SII - Certification process'),
            ('SII', 'www.sii.cl'),
            ('SII MiPyme', 'SII - Portal MiPyme')],
        'DTE Service Provider', help='''Please select your company service \
provider for DTE service. Select \'None\' if you use manual invoices, fiscal \
controllers or MiPYME Sii Service. Also take in account that if you select \
\'www.sii.cl\' you will need to provide SII exempt resolution number in order \
to be legally enabled to use the service. If your service provider is not \
listed here, please send us an email to soporte@blancomartin.cl in order to \
add the option.''', default='')
    dte_resolution_number = fields.Char('SII Exempt Resolution Number',
                                        help='''This value must be provided \
and must appear in your pdf or printed tribute document, under the electronic \
stamp to be legally valid.''')
    dte_resolution_date = fields.Date('SII Exempt Resolution Date')
    sii_regional_office_id = fields.Many2one(
        'sii.regional.offices', string='SII Regional Office')
    dte_username = fields.Char('DTE Username', help='''Please enter the value \
issued by the DTE Service provider''')
    dte_password = fields.Char(
        'DTE Password/Token', help='''In LibreDTE case, this value is the \
token. In other cases, the pair username/password is needed.''')
    dte_tributarias = fields.Selection(
        [(1, '1'), (2, '2')], string='Copias Tributarias', default=1,
        help=u'''Cantidad de copias tributarias.''')
    dte_cedibles = fields.Selection(
        [(0, ''), (1, '1'), (2, '2')], string='Copias Cedibles', default=0,
        help=u'''Cantidad de copias cedibles. Para que esta característica \
funcione, deberá habilitar la iimpresión de cedible en LibreDTE.''')

    @api.onchange('dte_service_provider')
    def _set_libredte_username(self):
        """
        cambiar dte username para libredte
        @author: Daniel Blanco Martin (daniel[at]blancomartin.cl)
        @version: 2016-06-16
        """
        if self.dte_service_provider in ['LIBREDTE']:
            self.username = 'X'

    @api.onchange('city_id')
    def _set_regional_office(self):
        if self.dte_service_provider in ['SIIHOMO', 'SII']:
            try:
                self.sii_regional_office_id = \
                    self.city_id.sii_regional_office_ids[0]
            except:
                _logger.info('Cannot assign regional office')

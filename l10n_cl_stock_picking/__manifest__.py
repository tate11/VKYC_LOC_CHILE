# -*- coding: utf-8 -*-
{   'active': True,
    'author': u'Daniel Santibáñez Polanco, Chilean Localization Team 10.0',
    'website': 'http://globalresponse.cl',
    'category': 'Stock/picking',
    'demo_xml': [],
    'depends': [
        'stock',
        'fleet',
        'delivery',
        'l10n_cl_invoice',
        'l10n_cl_base_rut',
        'l10n_cl_partner_activities',
        'l10n_cl_dte',
        ],
    'description': u'''
\n\nMódulo de Guías de Despacho de la localización Chilena.\n\n\nIncluye:\n
- Configuración de libros, diarios (journals) y otros detalles para Guías de despacho en Chile.\n
- Asistente para configurar los talonarios de facturas, boletas, guías de despacho, etc.
''',
    'init_xml': [],
    'installable': True,
    'license': 'AGPL-3',
    'name': u'Chile - Sistema de apoyo a la guías de despacho',
    'test': [],
    'data': [
        'security/ir.model.access.csv',
        'views/dte.xml',
        'views/stock_picking.xml',
        'views/layout.xml',
        'views/libro_guias.xml',
        'wizard/masive_send_dte.xml',
    ],
    'version': '10.0.3.0',
    'installable': False,
}

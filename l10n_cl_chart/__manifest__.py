# -*- coding: utf-8 -*-
# Part of Odoo. See LICENSE file for full copyright and licensing details.

# Copyright (c) 2016 Blanco Martin y Asociados - Nelson Ramírez Sánchez http://www.bmya.cl

{
    'name': 'Chile Localization Chart Account BMyA',
    'version': '10.0.2.2.0',
    'description': """
Chilean accounting chart and tax localization.
==============================================
Plan contable chileno e impuestos de acuerdo a disposiciones vigentes,
basado en plan de cuentas de Superintendencia de Valores y Seguros de
Chile, con algunas cuentas agregadas en base a experiencias de
implementación

    """,
    'author': 'Blanco Martin & Asociados',
    'website': 'http://www.bmya.cl',
    'category': 'Localization',
    'depends': ['account'],
    'data': [
        'data/l10n_cl_chart_tags.xml',
        'data/l10n_cl_chart_data.xml',
        'data/account_tax_data.xml',
        'data/account_chart_template_data.yml'
    ],
    'installable': True,
}

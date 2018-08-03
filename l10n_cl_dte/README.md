# l10n_cl_dte

Odoo - Chilean electronic invoicing
===================================

You can check functionality in the following blog:

http://blancomartin.cl/blog


This module is in develop, and intented to deliver electronic invoices for
Chile.

It provides infrastructure to connect to several electronic invoicing 
service provider, and - in develop to SII.
It also allows you to generate records in Odoo of electronic invoices vouchers.

You can also extend this module to include more providers.

Regarding SII connection, it interacts with these already developed modules:

l10n_cl_partner_activities
l10n_cl_base_rut
l10n_cl_invoice
l10n_cl_dte_caf

TO-DO:
- Connection to SII
- Authentication using signature key certificate (provided by module 
"user_signature_key" by ourselves - BMyA).

## Credits
### This module is fully authored by BMyA, and inspired by 
argentinean localization project, but just in forms, not in code.


## Créditos
### Este módulo es de autoría total de BMyA e inspirado por
el proyecto de localización argentina, pero solo en formas, no en código.


![Logo BMyA](https://blancomartin.cl/website/image/ir.attachment/9711_e6d1eea/datas)
**Blanco Martin & Asociados EIRL** - http://blancomartin.cl


#### Versions:
8.1.0.0.0
- This version includes multiple references, for invoices and credit notes.

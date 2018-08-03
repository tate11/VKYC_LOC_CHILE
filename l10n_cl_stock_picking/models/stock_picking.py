# -*- coding: utf-8 -*-
from odoo import osv, models, fields, api, _
from odoo.exceptions import except_orm, UserError
import openerp.addons.decimal_precision as dp
from odoo.tools.float_utils import float_compare, float_round
import logging
_logger = logging.getLogger(__name__)


class StockPicking(models.Model):
    _inherit = "stock.picking"

    def get_document_class_default(self, document_classes):
        if self.turn_issuer.vat_affected not in ['SI', 'ND']:
            exempt_ids = [
                self.env.ref('l10n_cl_invoice.dc_y_f_dtn').id,
                self.env.ref('l10n_cl_invoice.dc_y_f_dte').id]
            for document_class in document_classes:
                if document_class.sii_document_class_id.id in exempt_ids:
                    document_class_id = document_class.id
                    break
                else:
                    document_class_id = document_classes.ids[0]
        else:
            document_class_id = document_classes.ids[0]
        return document_class_id

    @api.onchange('journal_id', 'company_id')
    def _set_available_issuer_turns(self):
        for rec in self:
            if rec.company_id:
                available_turn_ids = rec.company_id.company_activities_ids
                for turn in available_turn_ids:
                    rec.turn_issuer = turn

    @api.one
    @api.onchange('pack_operation_product_ids', 'currency_id', 'company_id')
    def _compute_amount(self):
        if self.pack_operation_product_ids and self.state not in ['draft']:
            for operation in self.pack_operation_product_ids:
                self.amount_untaxed += operation.subtotal
                if operation.operation_line_tax_ids:
                    taxes = operation.operation_line_tax_ids.compute_all(
                        operation.price_unit, self.currency_id,
                        operation.qty_done, product=operation.product_id,
                        partner=self.partner_id)['taxes']
                    for tax in taxes:
                        self.amount_tax += tax['amount']
            self.amount_total = self.amount_untaxed + self.amount_tax
        elif self.move_lines:
            for move in self.move_lines:
                self.amount_untaxed += move.subtotal
                if move.move_line_tax_ids:
                    taxes = move.move_line_tax_ids.compute_all(
                        move.price_unit, self.currency_id,
                        move.product_uom_qty, product=move.product_id,
                        partner=self.partner_id)['taxes']
                    for tax in taxes:
                        self.amount_tax += tax['amount']
            self.amount_total = self.amount_untaxed + self.amount_tax

    amount_untaxed = fields.Monetary(
        compute='_compute_amount', string='Untaxed Amount')
    amount_tax = fields.Monetary(
        compute='_compute_amount', string='Taxes')
    amount_total = fields.Monetary(
        compute='_compute_amount', string='Total')
    currency_id = fields.Many2one(
        'res.currency', string='Currency',
        required=True, readonly=True, states={'draft': [('readonly', False)]},
        default=lambda self: self.env.user.company_id.currency_id,
        track_visibility='always')
    sii_batch_number = fields.Integer(
        copy=False,
        string='Batch Number',
        readonly=True,
        help='Batch number for processing multiple invoices together')

    turn_issuer = fields.Many2one(
        'partner.activities',
        'Giro Emisor', store=True, required=False,
        readonly=True,
        states={'assigned': [('readonly', False)],
                'draft': [('readonly', False)], })

    partner_turn = fields.Many2one(
        'partner.activities',
        'Giro',
        store=True,
        readonly=True, states={
            'assigned': [('readonly', False)],
            'draft': [('readonly', False)], })

    activity_description = fields.Many2one(
        'sii.activity.description',
        'Giro',
        related="partner_id.activity_description",
        readonly=True,
        states={
            'assigned': [('readonly', False)],
            'draft': [('readonly', False)], })
    sii_document_number = fields.Char(
        string='Document Number',
        copy=False,
        readonly=True,)
    responsability_id = fields.Many2one(
        'sii.responsability',
        string='Responsability',
        related='partner_id.responsability_id',
        store=True,
        )
    formated_vat = fields.Char(
        string='Main company ID',
        related='partner_id.formated_vat',)
    next_number = fields.Integer(
        related='picking_type_id.sequence_id.number_next_actual',
        string='Next Document Number',
        readonly=True)
    use_documents = fields.Boolean(
        string='Use Documents?',
        readonly=True)
    reference = fields.One2many(
        'stock.picking.referencias', 'stock_picking_id',
        readonly=False, states={'done': [('readonly', True)]})
    transport_type = fields.Selection(
        [('2', 'Despacho por cuenta de empresa'),
         ('1', 'Despacho por cuenta del cliente'),
         ('3', 'Despacho Externo'), ('0', 'Sin Definir')],
        string="Tipo de Despacho",
        required=True,
        default="2",
        readonly=False, states={'done': [('readonly', True)]})
    move_reason = fields.Selection(
        [('1', 'Operación constituye venta'), ('2', 'Ventas por efectuar'),
         ('3', 'Consignaciones'), ('4', 'Entrega Gratuita'),
         ('5', 'Traslados Internos'),
         ('6', 'Otros traslados no venta'), ('7', 'Guía de Devolución'),
         ('8', 'Traslado para exportación'), ('9', 'Ventas para exportación')],
        string='Razón del traslado',
        default="1",
        required=True,
        readonly=False, states={'done': [('readonly', True)], })
    vehicle = fields.Many2one(
        'fleet.vehicle', string="Vehículo", readonly=False,
        states={'done': [('readonly', True)]})
    chofer = fields.Many2one(
        'res.partner', string="Chofer", readonly=False,
        states={'done': [('readonly', True)]})
    patente = fields.Char(
        string="Patente", readonly=False, states={'done': [('readonly', True)]})
    contact_id = fields.Many2one(
        'res.partner', string="Contacto", readonly=False,
        states={'done': [('readonly', True)]})

    @api.onchange('vehicle')
    def _set_driver(self):
        self.chofer = self.vehicle.driver_id
        self.patente = self.vehicle.license_plate

    @api.onchange('carrier_id')
    def _set_driver_from_carrier(self):
        self.chofer = self.carrier_id.partner_id

    @api.onchange('pack_operation_product_ids')
    def _set_values(self):
        for rec in self:
            if rec.pack_operation_product_ids:
                for m in rec.pack_operation_product_ids:
                    for l in rec.move_lines_related:
                        if l.product_id.id == m.product_id.id:
                            m.price_unit = l.price_unit
                            m.discount = l.discount
                            m.operation_line_tax_ids = l.move_line_tax_ids
                if not m.price_unit > 0 or not m.name:
                    m.price_unit = m.product_id.lst_price
                    if not m.name:
                        m.name = m.product_id.name
                    m.operation_line_tax_ids = m.product_id.taxes_id
                    # @TODO mejorar asignación

    def _prepare_pack_ops(
            self, cr, uid, picking, quants, forced_qties, context=None):
        """ returns a list of dict, ready to be used in create() of
        stock.pack.operation.
        :param picking: browse record (stock.picking)
        :param quants: browse record list (stock.quant). List of quants
        associated to the picking
        :param forced_qties: dictionary showing for each product (keys)
        its corresponding quantity (value) that is not covered by the quants
        associated to the picking
        """
        def _picking_putaway_apply(product):
            # Search putaway strategy
            if product_putaway_strats.get(product.id):
                location = product_putaway_strats[product.id]
            else:
                location = self.pool.get(
                    'stock.location').get_putaway_strategy(
                    cr, uid, picking.location_dest_id, product, context=context)
                product_putaway_strats[product.id] = location
            return location or picking.location_dest_id.id

        # If we encounter an UoM that is smaller than the default UoM or
        # the one already chosen, use the new one instead.
        product_uom = {}  # Determines UoM used in pack operations
        location_dest_id = None
        location_id = None
        for move in [x for x in picking.move_lines if x.state not in (
                'done', 'cancel')]:
            if not product_uom.get(move.product_id.id):
                product_uom[move.product_id.id] = move.product_id.uom_id
            if move.product_uom.id != move.product_id.uom_id.id and \
                            move.product_uom.factor > \
                            product_uom[move.product_id.id].factor:
                product_uom[move.product_id.id] = move.product_uom
            if not move.scrapped:
                if location_dest_id and \
                                move.location_dest_id.id != location_dest_id:
                    raise UserError(_('The destination location must be the \
same for all the moves of the picking.'))
                location_dest_id = move.location_dest_id.id
                if location_id and move.location_id.id != location_id:
                    raise UserError(_('The source location must be the same \
for all the moves of the picking.'))
                location_id = move.location_id.id

        pack_obj = self.pool.get("stock.quant.package")
        quant_obj = self.pool.get("stock.quant")
        vals = []
        qtys_grouped = []
        lots_grouped = {}
        #for each quant of the picking, find the suggested location
        quants_suggested_locations = {}
        product_putaway_strats = {}
        for quant in quants:
            if quant.qty <= 0:
                continue
            suggested_location_id = _picking_putaway_apply(quant.product_id)
            quants_suggested_locations[quant] = suggested_location_id
        # find the packages we can movei as a whole
        top_lvl_packages = self._get_top_level_packages(
            cr, uid, quants_suggested_locations, context=context)
        # and then create pack operations for the top-level packages found
        for pack in top_lvl_packages:
            pack_quant_ids = pack_obj.get_content(
                cr, uid, [pack.id], context=context)
            pack_quants = quant_obj.browse(
                cr, uid, pack_quant_ids, context=context)
            vals.append({
                    'picking_id': picking.id,
                    'package_id': pack.id,
                    'product_qty': 1.0,
                    'location_id': pack.location_id.id,
                    'location_dest_id': quants_suggested_locations[
                        pack_quants[0]],
                    'owner_id': pack.owner_id.id,
                })
            #remove the quants inside the package so that they are
            # excluded from the rest of the computation
            for quant in pack_quants:
                del quants_suggested_locations[quant]
        # Go through all remaining reserved quants and group by product,
        # package, owner, source location and dest location
        # Lots will go into pack operation lot object
        for quant, dest_location_id in quants_suggested_locations.items():
            key = (quant.product_id.id, quant.package_id.id, quant.owner_id.id,
                   quant.location_id.id, dest_location_id)
            qtys_grouped.extend([{'key':key,'value': quant.qty}])
            if quant.product_id.tracking != 'none' and quant.lot_id:
                lots_grouped.setdefault(
                    key, {}).setdefault(quant.lot_id.id, 0.0)
                lots_grouped[key][quant.lot_id.id] += quant.qty

        # Do the same for the forced quantities (in cases of force_assign or
        # incomming shipment for example)
        for it in forced_qties:
            product = it['key']
            qty = it['value']
            if qty <= 0:
                continue
            suggested_location_id = _picking_putaway_apply(product)
            key = (product.id, False, picking.owner_id.id,
                   picking.location_id.id, suggested_location_id)
            qtys_grouped.extend(
                [{
                    'key': key, 'value': qty, 'name': it['name'],
                    'price_unit': it['price_unit'], }])
        # Create the necessary operations for the grouped quants and remaining qtys
        uom_obj = self.pool.get('product.uom')
        prevals = {}
        for it in qtys_grouped:
            key = it['key']
            qty = it['value']
            product = self.pool.get("product.product").browse(
                cr, uid, key[0], context=context)
            uom_id = product.uom_id.id
            qty_uom = qty
            if product_uom.get(key[0]):
                uom_id = product_uom[key[0]].id
                qty_uom = uom_obj._compute_qty(
                    cr, uid, product.uom_id.id, qty, uom_id)
            pack_lot_ids = []
            if lots_grouped.get(key):
                for lot in lots_grouped[key].keys():
                    pack_lot_ids += [(0, 0, {
                        'lot_id': lot,
                        'qty': 0.0,
                        'qty_todo': lots_grouped[key][lot], })]
            val_dict = {
                'picking_id': picking.id,
                'product_qty': qty_uom,
                'product_id': key[0],
                'package_id': key[1],
                'owner_id': key[2],
                'location_id': key[3],
                'location_dest_id': key[4],
                'product_uom_id': uom_id,
                'pack_lot_ids': pack_lot_ids,
            }
            if 'name' in it:
                val_dict['name'] = it['name']
            if 'price_unit' in it:
                val_dict['price_unit'] = it['price_unit']
            if (key[0],it['name']) in prevals:
                prevals[(key[0],it['name'])].append(val_dict)
            else:
                prevals[(key[0],it['name'])] = [val_dict]
        # prevals var holds the operations in order to create them in the
        # same order than the picking stock moves if possible
        processed_products = set()
        for move in [
            x for x in picking.move_lines if x.state not in ('done', 'cancel')]:
            if (move.product_id.id, move.name) not in processed_products:
                vals += prevals.get((move.product_id.id, move.name), [])
                processed_products.add((move.product_id.id, move.name))
        return vals

    @api.cr_uid_ids_context
    def do_prepare_partial(self, cr, uid, picking_ids, context=None):
        context = context or {}
        pack_operation_obj = self.pool.get('stock.pack.operation')

        #get list of existing operations and delete them
        existing_package_ids = pack_operation_obj.search(cr, uid, [
            ('picking_id', 'in', picking_ids)], context=context)
        if existing_package_ids:
            pack_operation_obj.unlink(cr, uid, existing_package_ids, context)
        for picking in self.browse(cr, uid, picking_ids, context=context):
            forced_qties = []
            # Quantity remaining after calculating reserved quants
            picking_quants = []
            #Calculate packages, reserved quants, qtys of this picking's moves
            for move in picking.move_lines:
                if move.state not in ('assigned', 'confirmed', 'waiting'):
                    continue
                move_quants = move.reserved_quant_ids
                picking_quants += move_quants
                forced_qty = (move.state == 'assigned') and \
                             move.product_qty - \
                             sum([x.qty for x in move_quants]) or 0
                # if we used force_assign() on the move, or if the
                # move is incoming, forced_qty > 0
                if float_compare(
                        forced_qty, 0,
                        precision_rounding=move.product_id.uom_id.rounding) > 0:
                    forced_qties.extend(
                        [{'key': move.product_id, 'value': forced_qty,
                          'name': move.name ,'price_unit': move.price_unit}])
            for vals in self._prepare_pack_ops(
                    cr, uid, picking, picking_quants,
                    forced_qties, context=context):
                vals['fresh_record'] = False
                pack_operation_obj.create(cr, uid, vals, context=context)
        #recompute the remaining quantities all at once
        self.do_recompute_remaining_quantities(
            cr, uid, picking_ids, context=context)
        self.write(cr, uid, picking_ids, {
            'recompute_pack_op': False}, context=context)

class StockLocation(models.Model):
    _inherit = 'stock.location'

    sii_document_class_id = fields.Many2one(
        'sii.document_class', 'Document Type', required=True)
    sequence_id = fields.Many2one(
        'ir.sequence', 'Entry Sequence', required=False,
        help="""This field contains the information related to the numbering \
        of the documents entries of this document type.""")
    sii_code = fields.Char(string="Código de Sucursal SII")

class Referencias(models.Model):
    _name = 'stock.picking.referencias'

    origen = fields.Char(string="Origin")
    sii_referencia_TpoDocRef =  fields.Many2one('sii.document_class',
        string="SII Reference Document Type")
    date = fields.Date(string="Fecha de la referencia")
    stock_picking_id = fields.Many2one(
        'stock.picking', ondelete='cascade', index=True, copy=False,
        string="Documento")

class StockPackOperation(models.Model):
    _inherit = "stock.pack.operation"

    def create(self, cr, uid, vals,context=None):
        picking_id = self.pool.get('stock.picking').browse(
            cr,uid,vals['picking_id'],context=context)
        for o in picking_id.move_lines:
            if vals['product_id'] == o.product_id.id and o.name == vals['name']:
                vals['subtotal'] = o.subtotal
                vals['discount'] = o.discount
                vals['operation_line_tax_ids'] = o.move_line_tax_ids.ids

        super(StockPackOperation,self).create(cr,uid,vals,context=context)

    @api.depends('picking_id.move_lines_related')
    @api.onchange('name', 'qty_done')
    def _set_values(self):
        for rec in self:
            for l in rec.picking_id.move_lines_related:
                if l.product_id.id == rec.product_id.id and l.name == rec.name:
                    rec.price_unit = l.price_unit
                    rec.discount = l.discount
                    rec.operation_line_tax_ids = l.move_line_tax_ids
            if not rec.price_unit > 0 or not rec.name:
                if not rec.name:
                    rec.name = rec.product_id.name
                rec.price_unit = rec.product_id.lst_price
                rec.operation_line_tax_ids = rec.product_id.taxes_id
                # @TODO mejorar asignación

    name = fields.Char(string="Nombre")

    subtotal = fields.Monetary(
        compute='_compute_amount', string='Subtotal')
    price_unit = fields.Monetary(string='Price')
    price_untaxed = fields.Monetary(string='Price Untaxed')

    operation_line_tax_ids = fields.Many2many('account.tax',
        'operation_line_tax', 'operation_line_id', 'tax_id',
            string='Taxes', domain=[
            ('type_tax_use', '!=', 'none'), '|', ('active', '=', False),
            ('active', '=', True)], oldname='invoice_line_tax_id')
    discount = fields.Monetary(string='Discount (%)')

    currency_id = fields.Many2one(
        'res.currency', string='Currency',
        required=True, readonly=True, states={'draft': [('readonly', False)]},
        default=lambda self: self.env.user.company_id.currency_id,
        track_visibility='always')

    @api.onchange(
        'price_unit', 'qty_done', 'product_id', 'operation_line_tax_ids')
    def _compute_amount(self):
        for rec in self:
            currency = rec.picking_id.currency_id or None
            price = rec.price_unit * (1 - (rec.discount or 0.0) / 100.0)
            taxes = False
            if rec.operation_line_tax_ids:
                taxes = rec.operation_line_tax_ids.compute_all(
                    price, currency, rec.qty_done, product=rec.product_id,
                    partner=rec.picking_id.partner_id)
            rec.subtotal = price_subtotal_signed = taxes['total_excluded'] \
                if taxes else rec.qty_done * price

class StockMove(models.Model):
    _inherit = 'stock.move'

    @api.model
    def create(self,vals):
        _logger.info(vals)
        #if 'linked_move_operation_ids' in vals:
        #    move = vals['linked_move_operation_ids'][0].move_id
        #    if move.procurement_id.sale_line_id:
        #        vals['operation_line_tax_ids'] = move.move_line_tax_ids.ids
        #        vals['price_untaxed'] = move.price_untaxed
        #        vals['price_unit'] = move.price_unit
        #        vals['discount'] = move.discount
        #        vals['subtotal'] = 0
        return super(StockMove,self).create(vals)

    @api.depends('picking_id.reference')
    @api.onchange('name')
    def _sale_prices(self):
        for rec in self:
            if rec.picking_id.reference:
                for ref in rec.picking_id.reference:
                    if ref.sii_referencia_TpoDocRef.sii_code in \
                            ['34','33']:# factura venta
                        inv = self.env['account.invoice'].search(
                            [('sii_document_number','=',ref.origen)])
                        for l in inv.invoice_lines:
                            if l.product_id.id == rec.product_id.id:
                                rec.price_unit = l.price_unit
                                rec.subtotal = l.subtotal
                                rec.discount = l.discount
                                rec.move_line_tax_ids = l.invoice_line_tax_ids
            if not rec.price_unit > 0 or not rec.name:
                rec.price_unit = rec.product_id.lst_price
                if not rec.name:
                	rec.name = rec.product_id.name
                rec.move_line_tax_ids = rec.product_id.taxes_id
                #  @TODO mejorar asignación

    @api.onchange('name','product_id','move_line_tax_ids','product_uom_qty')
    def _compute_amount(self):
        for rec in self:
            currency = rec.picking_id.currency_id or None
            price = rec.price_unit * (1 - (rec.discount or 0.0) / 100.0)
            taxes = False
            if rec.move_line_tax_ids:
                taxes = rec.move_line_tax_ids.compute_all(
                    price, currency, rec.product_uom_qty,
                    product=rec.product_id, partner=rec.picking_id.partner_id)
            rec.subtotal = price_subtotal_signed = taxes['total_excluded'] \
                if taxes else rec.product_uom_qty * price

    name = fields.Char(string="Nombre")

    subtotal = fields.Monetary(
        compute='_compute_amount', string='Subtotal')

    price_unit = fields.Monetary(string='Price')
    price_untaxed = fields.Monetary(
        compute='_sale_prices', string='Price Untaxed')
    move_line_tax_ids = fields.Many2many(
        'account.tax', 'move_line_tax_ids', 'move_line_id', 'tax_id',
        string='Taxes',
        domain=[('type_tax_use', '!=', 'none'),
                '|', ('active', '=', False), ('active', '=', True)],
        oldname='invoice_line_tax_id')
    discount = fields.Monetary(string='Discount (%)')
    currency_id = fields.Many2one(
        'res.currency', string='Currency',
        required=True, readonly=True, states={'draft': [('readonly', False)]},
        default=lambda self: self.env.user.company_id.currency_id,
        track_visibility='always')

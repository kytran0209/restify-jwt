const errors = require('restify-errors');
const Customer = require('../models/Customer');

module.exports = (server) => {
	// Get Customers
	server.get('/customers', async(req, res, next) => {
		try {
			const customers = await Customer.find({});
			res.send(customers);
			next();
		} catch(error) {
			return next(new errors.InvalidContentError(err));
		}
	});

	// Add Customer
	server.post('/customers', async(req, res, next) => {
		// Check for JSON
		if (!req.is('application/json')) {
			return next(new errors.InvalidContentError('Expects application/json'));
		}

		const {name, email, balance} = req.body;

		const customer = new Customer({
			name, email, balance
		});

		try {
			await customer.save();
			res.send(201);
			next();
		} catch(error) {
			return next(new errors.InternalError(error.message));
		}
	});

	// Get Single Customer
	server.get('/customers/:id', async(req, res, next) => {
		try {
			const customers = await Customer.findById(req.params.id);
			res.send(customers);
			next();
		} catch(error) {
			return next(new errors.ResourceNotFoundError(`There is no customer with the id of ${req.params.id}`));
		}
	});

	// Update Customer
	server.put('/customers/:id', async(req, res, next) => {
		// Check for JSON
		if (!req.is('application/json')) {
			return next(new errors.InvalidContentError('Expects application/json'));
		}


		try {
			await Customer.findOneAndUpdate({_id: req.params.id}, req.body);
			res.send(200);
			next();
		} catch(error) {
			return next(new errors.ResourceNotFoundError(`There is no customer with the id of ${req.params.id}`));
		}
	});

	// Delete Customer
	server.del('/customers/:id', async(req, res,next) => {
		try {
			await Customer.findOneAndRemove({_id: req.params.id});
			res.send(204);
			next();
		} catch(error) {
			return next(new errors.ResourceNotFoundError(`There is no customer with the id of ${req.params.id}`));
		}
	})
}


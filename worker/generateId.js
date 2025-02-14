const crypto = require('crypto');

const generateId = function (prefix) {
    return new Promise((resolve, reject) => { 
        crypto.randomBytes(8, (err, buffer) => { 
            if (err) {
                reject(err); 
                return;
            }
            const generatedId = `${prefix}_${Date.now()}_${buffer.toString('hex')}`;
            resolve(generatedId); // Resolve with the ID
        });
    });
};

module.exports = generateId;
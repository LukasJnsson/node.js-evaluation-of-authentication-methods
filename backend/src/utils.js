

/**
 * Generate id
 * @param {Number} length number of character
 * @returns {String} generated id
 */
export const generateId = (length) => {
    let id = "";
    const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz";
    while (id.length !== length) {
      const index = Math.floor(crypto.getRandomValues(new Uint8Array(1))[0] / 4);
      if (index >= alphabet.length) {
        continue;
      };
      id += alphabet[index];
    };
    return id;
};
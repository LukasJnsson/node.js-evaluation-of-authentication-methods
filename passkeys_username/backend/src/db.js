
/**
 * User database
 */
let users = [];


/**
 * Database operations
 */
export default {
  /**
   * Add user
   * @param {Object} user User object
   * @returns {Object} User object
   */
  addUser(user) {
    for (const existingUser of users) {
      if (
        user.username === existingUser.username 
        || user.credential_id === existingUser.credential_id 
        ) {
        throw new Error("Invalid credentials!");
      };
    };
    users.push(user);
    return user;
  },

  /**
   * Get user by credential id
   * @param {String} credentialId User credential id
   * @returns {Object} User object
   */
  getUserByCredentialId(credentialId) {
    return users.find(existingUser => existingUser.credential_id === credentialId);
  },

  /**
   * Get user by username
   * @param {String} username Username
   * @returns {Object} User object
   */
  getUserByUsername(username) {
    return users.find(existingUser => existingUser.username === username);
  },

  /**
   * Get users
   * @returns {Array<Object>} Array with the user objects
   */
  getUsers() {
    return [...users]; // Shallow copy
  }
};
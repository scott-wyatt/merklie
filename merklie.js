const sha3512 = require('js-sha3').sha3_512
const sha3384 = require('js-sha3').sha3_384
const sha3256 = require('js-sha3').sha3_256
const sha3224 = require('js-sha3').sha3_224
const crypto = require('crypto')

module.exports = class Merklie {
  constructor (treeOptions) {

    // Set Defaults
    this.tree = {}
    this.tree.leaves = []
    this.tree.levels = []
    this.tree.isReady = false
    this.hashType = 'sha256'
    this.validHashTypes = ['SHA3-224','SHA3-256','SHA3-384','SHA3-512','sha256', 'md5', 'none']

    // if tree options were supplied, then process them
    if (treeOptions && treeOptions.hashType !== undefined) {
      // set the hash function to the user's choice
      this.hashType = treeOptions.hashType
    }

  }

  /**
   * Returns a hashed value
   * @param value
   * @returns {number[]}
   */
  hashFunction(value) {
    if (this.hashType === 'SHA3-224') {
      return Buffer.from(sha3224.array(value))
    }
    else if (this.hashType === 'SHA3-256') {
      return Buffer.from(sha3256.array(value))
    }
    else if (this.hashType === 'SHA3-384') {
      return Buffer.from(sha3384.array(value))
    }
    else if (this.hashType === 'SHA3-512') {
      return Buffer.from(sha3512.array(value))
    }
    else if (this.hashType === 'none') {
      return Buffer.from(value)
    }
    // use default node.js crypto lib
    else {
      return crypto.createHash(this.hashType).update(value).digest()
    }
  }

  /**
   * Get the Hash Type Library
   * @returns {string}
   */
  get hashLib() {
    return this.hashType
  }

  /**
   * Set the Hash Type Library and Reset the Tree
   * @param {string} hash
   */
  set hashLib (hash) {
    if (this.validHashTypes.indexOf(hash) === -1) {
      throw new Error(`${hash} is an invalid selection, choose either ${this.validHashTypes.join(', ')}`)
    }
    // Reset the tree for a new hash type
    this.resetTree()
    // Reset the hash type lib
    this.hashType = hash
  }

  /**
   * Returns a re-hashed hex
   * @param {*} value
   * @param {boolean} noHash
   * @returns {*}
   */
  reHash (value, noHash) {
    // If this is already a hash, there is no point to hash it again.
    if (!noHash) {
      // If this is JSON, then we need to stringify it
      if (typeof value === 'object') {
        value = JSON.stringify(value)
      }
      // Hash the value
      value = this.hashFunction(value)
    }
    return this._getBuffer(value).toString('hex')
  }

  /**
   * Resets the current tree to empty
   * @returns {{}}
   */
  resetTree () {
    this.tree = {}
    this.tree.leaves = []
    this.tree.levels = []
    this.tree.isReady = false
    return this.tree
  }

  /**
   * Add a leaf to the tree
   * @param value:
   * @param {boolean} doHash: Accepts hash value as a Buffer or hex string
   * @param {boolean} returnHash
   * @returns {number}
   */
  addLeaf (value, doHash, returnHash) {
    this.tree.isReady = false

    if (doHash) {
      // If this is JSON, then we need to stringify it
      if (typeof value === 'object') {
        value = JSON.stringify(value)
      }
      // If this is a number, then we need to stringify it
      if (typeof value === 'number') {
        value = value.toString()
      }
      // Hash the value
      value = this.hashFunction(value)
    }

    const buffer = this._getBuffer(value)
    // Add the leaf to the tree
    this.tree.leaves.push(buffer)

    if (returnHash) {
      return buffer.toString('hex')
    }
    else {
      return this.tree.leaves.length - 1
    }
  }

  /**
   * Add a leaves to the tree
   * @param valuesArray: Accepts hash values as an array of Buffers or hex strings
   * @param {boolean} doHash
   * @param {boolean} returnHash
   * @returns {[number|string]}
   */
  addLeaves (valuesArray, doHash, returnHash) {
    // Set Values array if empty
    valuesArray = valuesArray || []
    // Leaves are being added so the tree is not ready
    this.tree.isReady = false
    // Add the leaf and return the index/hash
    return valuesArray.map((value) => {
      return this.addLeaf(value, doHash, returnHash)
    })
  }

  /**
   * Returns a leaf at the given index
   * @param index
   * @param {boolean} asBinary
   * @returns {*}
   */
  getLeaf (index, asBinary) {
    if (typeof index === 'number') {
      // do nothing
    }
    else if (index instanceof Buffer) {
      index = this._bufferIndex(index)
      // if the index is undefined, null or -1
      if (index === 'undefined' || index === null || index === -1) {
        return null
      }
    }
    else if (typeof index === 'string' && this._isHex(index)) {
      index = this._bufferIndex(this._getBuffer(index))
      // if the index is undefined, null or -1
      if (index === 'undefined' || index === null || index === -1) {
        return null
      }
    }
    else {
      throw new Error(`Bad Value - "${index}" should be a number, hex string, or buffer`)
    }
    // if index is out of array bounds
    if (index < 0 || index > this.tree.leaves.length - 1) {
      return null
    }
    if (asBinary) {
      return this.tree.leaves[index]
    }
    else {
      return this.tree.leaves[index].toString('hex')
    }
  }

  /**
   * Returns leaves at the given indexes
   * @param indexes
   * @param {boolean} asBinary
   * @returns {*}
   */
  getLeaves (indexes, asBinary) {
    return indexes.map(index => {
      return this.getLeaf(index, asBinary)
    })
  }

  /**
   * Returns the number of leaves added to the tree
   * @returns {Number}
   */
  getLeafCount () {
    return this.tree.leaves.length
  }

  /**
   * Returns the ready state of the tree
   * @returns {boolean}
   */
  getTreeReadyState () {
    return this.tree.isReady
  }

  /**
   * Generates the merkle tree
   * @param doubleHash
   * @returns {boolean}
   */
  makeTree (doubleHash) {
    this.tree.isReady = false

    // Only run this process if there are leaves in the tree
    if (this.tree.leaves.length > 0) {
      this.tree.levels = []
      this.tree.levels.unshift(this.tree.leaves)
      while (this.tree.levels[0].length > 1) {
        this.tree.levels.unshift(this._calculateNextLevel(doubleHash))
      }
    }
    // Set tree is ready
    return this.tree.isReady = true
  }

  /**
   * Generates a Bitcoin style merkle tree
   * @param doubleHash
   * @returns {boolean}
   */
  makeBTCTree (doubleHash) {
    this.tree.isReady = false

    // skip this whole process if there are no leaves added to the tree
    if (this.tree.leaves.length > 0) {
      this.tree.levels = []
      this.tree.levels.unshift(this.tree.leaves)
      while (this.tree.levels[0].length > 1) {
        this.tree.levels.unshift(this._calculateBTCNextLevel(doubleHash))
      }
    }
    // Set tree is ready
    return this.tree.isReady = true
  }

  /**
   * Returns the merkle root value for the tree
   * @param {boolean} asBinary
   * @returns {null|Buffer|string}
   */
  getMerkleRoot (asBinary) {
    // If the Tree isn't ready
    if (!this.tree.isReady || this.tree.levels.length === 0) {
      return null
    }
    if (asBinary) {
      return this.tree.levels[0][0]
    }
    else {
      return this.tree.levels[0][0].toString('hex')
    }
  }

  /**
   * Returns the proof for a leaf at the given index as an array of merkle siblings in hex format
   * @param index
   * @param asBinary
   * @returns {[]}
   */
  getProof (index, asBinary) {
    const currentRowIndex = this.tree.levels.length - 1
    const proof = []

    // If the Tree isn't ready return null
    if (!this.tree.isReady) {
      return null
    }

    // Convert Index to a number
    if (typeof index === 'number') {
      // do nothing
    }
    else if (index instanceof Buffer) {
      index = this._bufferIndex(index)
    }
    else if (typeof index === 'string' && this._isHex(index)) {
      index = this._bufferIndex(this._getBuffer(index))
    }
    else {
      throw new Error(`Bad Value - "${index}" should be a number, hex string, or buffer`)
    }

    // If the index it out of the bounds of the leaf array
    if (index < 0 || index > this.tree.levels[currentRowIndex].length - 1) {
      return null
    }

    for (let x = currentRowIndex; x > 0; x--) {
      const currentLevelNodeCount = this.tree.levels[x].length
      // skip if this is an odd end node
      if (index === currentLevelNodeCount - 1 && currentLevelNodeCount % 2 === 1) {
        index = Math.floor(index / 2)
        continue
      }

      // determine the sibling for the current index and get its value
      const isRightNode = index % 2
      const siblingIndex = isRightNode ? (index - 1) : (index + 1)

      if (asBinary) {
        proof.push(Buffer.from(isRightNode ? [0x00] : [0x01]))
        proof.push(this.tree.levels[x][siblingIndex])
      }
      else {
        const sibling = {}
        const siblingPosition = isRightNode ? 'left' : 'right'
        sibling[siblingPosition] = this.tree.levels[x][siblingIndex].toString('hex')
        // Add the sibling to the proof
        proof.push(sibling)
      }
      // set index to the parent index
      index = Math.floor(index / 2)
    }
    // Return the proof as object
    return proof.reduce(function(result, item, index) {
      result[index] = item // [left, right]
      return result
    }, {})
  }

  /**
   * Takes a proof array, a target hash value, and a merkle root
   * Checks the validity of the proof and return true or false
   * @param proof
   * @param targetHash
   * @param merkleRoot
   * @param doubleHash
   * @returns {boolean}
   */
  validateProof (proof, targetHash, merkleRoot, doubleHash) {
    targetHash = this._getBuffer(targetHash)
    merkleRoot = this._getBuffer(merkleRoot)

    // If no siblings, single item tree, so the hash should also be the root
    if (!proof[0]) {
      return targetHash.equals(merkleRoot)
    }

    let proofHash = targetHash
    for (let x in proof) {
      // If the sibling is a left node
      if (proof[x].left) {
        // If this is double hashed
        if (doubleHash) {
          proofHash = this.hashFunction(this.hashFunction(Buffer.concat([this._getBuffer(proof[x].left), proofHash])))
        }
        else {
          proofHash = this.hashFunction(Buffer.concat([this._getBuffer(proof[x].left), proofHash]))
        }
      }
      // then the sibling is a right node
      else if (proof[x].right) {
        if (doubleHash) {
          proofHash = this.hashFunction(this.hashFunction(Buffer.concat([proofHash, this._getBuffer(proof[x].right)])))
        }
        else {
          proofHash = this.hashFunction(Buffer.concat([proofHash, this._getBuffer(proof[x].right)]))
        }
      }
      // no left or right designation exists, proof is invalid
      else {
        return false
      }
    }
    // compare the proof to the root
    return proofHash.equals(merkleRoot)
  }

  /**
   * Dehdyrades the tree leaf buffers into hex
   * @param toString
   * @returns {string|[]}
   */
  dehydrate(toString) {
    const hexed = []

    if (!this.tree.isReady) {
      return null
    }

    this.tree.leaves.forEach((value) => {
      hexed.push(this._getHex(value))
    })

    if (toString) {
      return JSON.stringify(hexed)
    }
    else {
      return hexed
    }
  }

  /**
   * Rehydrates a String or JSON to buffers
   * @param leaves
   * @returns {boolean}
   */
  rehydrate(leaves) {
    // Reset the tree
    this.resetTree()

    if (typeof leaves === 'string') {
      leaves = JSON.parse(leaves)
    }

    // Push the leaves into the tree
    leaves.forEach(leaf => {
      this.tree.leaves.push(this._getBuffer(leaf))
    })

    // Rebuild the tree to ready state
    return this.makeTree()
  }
  /**
   * Internally, trees are made of nodes containing Buffer values only
   * This helps ensure that leaves being added are Buffers, and will convert hex to Buffer if needed
   * @param value
   * @returns {Buffer}
   * @private
   */
  _getBuffer (value) {
    // If we already have a buffer, so return it
    if (value instanceof Buffer) {
      return value
    }
    // If the value is a hex string, convert to buffer and return
    else if (this._isHex(value)) {
      return Buffer.from(value, 'hex')
    }
    // If the value is neither buffer nor hex string, will not process this, throw error
    else {
      throw new Error(`Bad hex value - "${value}"`)
    }
  }

  _bufferIndex (buffer) {
    let a
    let i = this.tree.leaves.length
    while (i--) {
      a = this.tree.leaves[i]
      if (a.equals(buffer)) {
        const index = i
        // Break the loop by setting it "false"
        i = -1
        // Return index
        return index
      }
    }
    return -1
  }

  /**
   * Returns if a value is HEX
   * @param value
   * @returns {boolean}
   * @private
   */
  _isHex (value) {
    const hexRegex = /^[0-9A-Fa-f]{2,}$/
    return hexRegex.test(value)
  }

  /**
   * Returns a Hex
   * @param value
   * @returns {*}
   * @private
   */
  _getHex (value) {
    if (value instanceof Buffer) {
      return value.toString('hex')
    }
    else if (this._isHex(value)) {
      return value
    }
    else {
      throw new Error(`Bad Value is not a Buffer or Hex - ${value}`)
    }
  }

  /**
   * Calculates the next level of node when building the merkle tree
   * These values are calcalated off of the current highest level, level 0 and will be prepended to the levels array
   * @param doubleHash
   * @returns {Array}
   * @private
   */
  _calculateNextLevel (doubleHash) {
    const nodes = []
    const topLevel = this.tree.levels[0]
    const topLevelCount = topLevel.length

    for (let x = 0; x < topLevelCount; x += 2) {
      // concatenate and hash the pair, add to the next level array, doubleHash if requested
      if (x + 1 <= topLevelCount - 1) {
        if (doubleHash) {
          nodes.push(this.hashFunction(this.hashFunction(Buffer.concat([topLevel[x], topLevel[x + 1]]))))
        }
        else {
          nodes.push(this.hashFunction(Buffer.concat([topLevel[x], topLevel[x + 1]])))
        }
      }
      // this is an odd ending node, promote up to the next level by itself
      else {
        nodes.push(topLevel[x])
      }
    }
    return nodes
  }

  /**
   * This version uses the BTC method of duplicating the odd ending nodes
   * @param doubleHash
   * @returns {Array}
   * @private
   */
  _calculateBTCNextLevel (doubleHash) {
    const nodes = []
    const topLevel = this.tree.levels[0]
    const topLevelCount = topLevel.length
    // If there is an odd count, duplicate the last element
    if (topLevelCount % 2 === 1) {
      topLevel.push(topLevel[topLevelCount - 1])
    }
    // concatenate and hash the pair, add to the next level array,
    for (let x = 0; x < topLevelCount; x += 2) {
      // doubleHash if requested
      if (doubleHash) {
        nodes.push(this.hashFunction(this.hashFunction(Buffer.concat([topLevel[x], topLevel[x + 1]]))))
      }
      else {
        nodes.push(this.hashFunction(Buffer.concat([topLevel[x], topLevel[x + 1]])))
      }
    }
    return nodes
  }
}

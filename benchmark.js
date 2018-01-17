'use strict'

const Benchmark = require('benchmark')

const suite = new Benchmark.Suite()
const crypto = require('crypto')
const Merklie = require('./merklie.js')

const merklie = new Merklie()

const leafCount = 75000
const leaves = []
// generate random hashes to use as leaves
for (let x = 0; x < leafCount; x++) {
  leaves.push(crypto.randomBytes(32).toString('hex'))
}

// add test to populate leaves, build tree, generate proofs, and reset tree
suite.add(leafCount + 'leaves', function () {
  // add random leaves to tree
  merklie.addLeaves(leaves)

  // build the merkle tree
  merklie.makeTree()

  // generate the merkle proofs for each leaf
  for (let x = 0; x < leafCount; x++) {
    merklie.getProof(x)
  }
  // clear the tree
  merklie.resetTree()

}).on('cycle', function (event) {
  console.log(String(event.target))
}).on('complete', function () {
  console.log(this[0].stats)
}).run({ 'async': true })

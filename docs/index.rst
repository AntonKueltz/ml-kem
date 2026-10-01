ML-KEM documentation
====================

This documentation is primarily focused on describing the package's API and usage. For details
on security, performance, implementation and development, see the
`README <https://github.com/AntonKueltz/ml-kem/blob/main/README.md>`_.

Reference
~~~~~~~~~

.. py:class:: ML_KEM(parameter_set: ParameterSet)

   A CCA-secure module-lattice-based key encapsulation mechanism (KEM).

   .. py:method:: key_gen() -> tuple[bytes, bytes]

      Generate a keypair (ek, dk) for use in the ML-KEM system.

      The key generation algorithm accepts no input, generates randomness internally, and produces an encapsulation
      key and a decapsulation key. While the encapsulation key can be made public, the decapsulation key shall
      remain private.

      :return: The (encapsulation key, decapulation key) pair.
      :rtype: :type:`tuple[bytes, bytes]`

   .. py:method:: encaps(ek: bytes) -> tuple[bytes, bytes]:

      Take an encapsulation key and produce a shared key and ciphertext.

      The shared key can be used as e.g. input to a KDF or as a key for a symmetric cipher between two parties.
      The ciphertext should be sent to the party in possession of the decapsulation key (the ciphertext is an
      encapsulation of the shared key).

      :param ek: The encapsulation key.
      :type ek: :type:`bytes`
      :return: The (shared key, ciphertext) pair.
      :rtype: :type:`tuple[bytes, bytes]`

   .. py:method:: decaps(dk: bytes, c: bytes) -> bytes:

      Takes a decapsulation key and ciphertext as input, does not use any randomness, and outputs a shared
      secret.

      The ciphertext should be produced by :func:`encaps` using the encapsulation key corresponding to the
      decapsulation key that was passed to this method. The result is the shared key, the same as the first value
      in the tuple output by :func:`encaps`.

      :param dk: The decapsulation key.
      :type dk: :type:`bytes`
      :param c:  The ciphertext.
      :type c: :type:`bytes`
      :return: The shared key.
      :rtype: :type:`bytes`

.. py:class:: ParameterSet

   An identifier for a collection of parameters from the standard

   Each set offers different levels of security. The default parameter set is :code:`ML_KEM_768`.

   ML_KEM_512
      Offers around 128 bits of security.

   ML_KEM_768
      Offers around 192 bits of security.

   ML_KEM_1024
      Offers around 256 bits of security.

Examples
~~~~~~~~

.. code-block:: python

   from mlkem import ML_KEM, ParameterSet

   kem = ML_KEM()          # default instantion uses the ML-KEM-768 param set
   ek, dk = kem.key_gen()  # encapsulation and decapsulation key
   k, c = kem.encaps(ek)   # shared secret key and ciphertext
   k_ = kem.decaps(dk, c)  # shared secret key

   kem1024 = ML_KEM(ParameterSet.ML_KEM_1024)  # use a higher security param set
   ek, dk = kem1024.key_gen()
   k, c = kem1024.encaps(ek)
   k_ = kem1024.decaps(dk, c)

In a less contrived scenario, Alice might run KeyGen and send the encapsulation key
to Bob. Bob would then run Encaps and generate a shared secret key and a ciphertext.
Bob would send the ciphertext to Alice, who would derive the shared secret key from the
ciphertext. Alice and Bob can then use the shared secret key to generate additional
secret material by passing it to a KDF, use the shared secret to directly key a symmetric
cipher like AES, etc.

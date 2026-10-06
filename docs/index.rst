ML-KEM documentation
====================

This documentation is primarily focused on describing the package's API and usage. For details
on security, performance, implementation and development, see the
`README <https://github.com/AntonKueltz/ml-kem/blob/main/README.md>`_.

Reference
~~~~~~~~~

.. py:class:: ML_KEM(parameter_set: ParameterSet)

   A CCA-secure module-lattice-based key encapsulation mechanism (KEM).

   .. py:method:: key_gen() -> tuple[EncapsKey, DecapsKey]

      Generate a keypair (ek, dk) for use in the ML-KEM system.

      The key generation algorithm accepts no input, generates randomness internally, and produces an encapsulation
      key and a decapsulation key. While the encapsulation key can be made public, the decapsulation key shall
      remain private.

      :return: The (encapsulation key, decapulation key) pair.
      :rtype: :type:`tuple[EncapsKey, DecapsKey]`

   .. py:method:: encaps(ek: EncapsKey) -> tuple[bytes, bytes]:

      Take an encapsulation key and produce a shared key and ciphertext.

      The shared key can be used as e.g. input to a KDF or as a key for a symmetric cipher between two parties.
      The ciphertext should be sent to the party in possession of the decapsulation key (the ciphertext is an
      encapsulation of the shared key).

      :param ek: The encapsulation key.
      :type ek: :type:`EncapsKey`
      :return: The (shared key, ciphertext) pair.
      :rtype: :type:`tuple[bytes, bytes]`

   .. py:method:: decaps(dk: DecapsKey, c: bytes) -> bytes:

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

.. py:class:: EncapsKey

   An encapsulation key for ML-KEM.

   Note this class stores the transpose of matrix :math:`A` as part of the object. This provides
   better performance for both the :func:`ML_KEM.encaps` and :func:`ML_KEM.decaps` operations, at the
   cost of a higher memory footprint for keys.

   .. py:method:: __bytes__() -> bytes:

      Serialize an encapsulation key to bytes.

      Note that the :math:`A` transpose matrix is not serialized, only the vector :math:`t` and bytes
      :code:`rho` are serialized. The coefficients of the polynomials comprising :math:`t` are all
      represented canonically in the range :math:`[0, Q)`.

      :return: Byte representation of the encapsulation key.
      :rtype: :type:`bytes`

   .. py:method:: to_bytes() -> bytes:

      See :func:`__bytes__`.

   .. py:staticmethod:: from_bytes(bytes) -> EncapsKey:

      Deserialize a byte sequence into an encapsulation key.

      This method will raise a :type:`ValueError` if the length of the byte sequence or the encoding
      of the data in the sequence is invalid. The parameter set for the key is inferred from the
      length of the byte sequence.

      :param serialized: The byte representation of the encapsulation key.
      :type serialized: :type:`bytes`
      :return: A deserialized encapsulation key object.
      :rtype: :type:`EncapsKey`

   .. py:property:: parameter_set() -> ParameterSet:

      The :type:`ParameterSet` that was used to generate the given instance of the class.

.. py:class:: DecapsKey

   A decapsulation key for ML-KEM.

   .. py:method:: __bytes__() -> bytes:

      Serialize a decapsulation key to bytes.

      :return: Byte representation of the decapsulation key.
      :rtype: :type:`bytes`

   .. py:method:: to_bytes() -> bytes:

      See :func:`__bytes__`.

   .. py:staticmethod:: from_bytes(bytes) -> DecapsKey:

      Deserialize a byte sequence into an decapsulation key.

      This method will raise a :type:`ValueError` if the length of the byte sequence or the encoding
      of the data in the sequence is invalid. The parameter set for the key is inferred from the
      length of the byte sequence.

      :param serialized: The byte representation of the decapsulation key.
      :type serialized: :type:`bytes`
      :return: A deserialized decapsulation key object.
      :rtype: :type:`DecapsKey`

   .. py:property:: parameter_set() -> ParameterSet:

      The :type:`ParameterSet` that was used to generate the given instance of the class.

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

Keys
----

When :func:`ML_KEM.key_gen` is run it returns two objects, :type:`EncapsKey` and a
:type:`DecapsKey`. You can serialize these to :type:`bytes` as follows.

.. code-block:: python

   from mlkem import ML_KEM

   kem = ML_KEM()
   ek, dk = kem.key_gen()
   ek_bytes = bytes(ek)  # ek.to_bytes() is also valid
   dk_bytes = bytes(dk)  # dk.to_bytes() is also valid

You can also deserialize bytes into a key, provided that the byte encoding is canonical and
compliant with FIPS-203.

.. code-block:: python

   from mlkem import DecapsKey, EncapsKey

   ek_bytes = b"..."  # canonically encodeed encapsulation key
   ek = EncapsKey.from_bytes(ek_bytes)

   dk_bytes = b"..."  # canonically encodeed decapsulation key
   dk = DecapsKey.from_bytes(dk_bytes)

You can also check which parameter set a key was generated with. A mismatch between a key and
the KEM parameter set will cause an error.

.. code-block:: python

   from mlkem import ML_KEM, ParameterSet

   kem512 = ML_KEM(ParameterSet.ML_KEM_512)
   kem768 = ML_KEM(ParameterSet.ML_KEM_768)
   ek512, _ = kem512.key_gen()

   ek512.parameter_set   # => ParameterSet.ML_KEM_512
   kem768.encaps(ek512)  # => ValueError: Key does not match this ML_KEM parameter set

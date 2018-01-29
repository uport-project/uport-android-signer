package com.uport.sdk.signer.storage

import android.content.Context
import android.content.Context.MODE_PRIVATE
import android.support.test.InstrumentationRegistry
import android.support.test.runner.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ProtectedSharedPreferencesTest {

    private lateinit var context: Context
    private lateinit var prefs: ProtectedSharedPreferences

    @Before
    fun before() {
        context = InstrumentationRegistry.getContext()
        val basePrefs = context.getSharedPreferences("test_prefs", MODE_PRIVATE)
        prefs = ProtectedSharedPreferences(basePrefs)
    }

    @Test
    fun contains() {

        val key = "some key"
        val value = "some value"

        prefs.edit().putString(key, value).apply()

        assertTrue(prefs.contains(key))
    }

    @Test
    fun getString() {

        val key = "some string key"
        val value = "some value"

        prefs.edit().putString(key, value).apply()

        assertEquals(value, prefs.getString(key, "not what I want"))
    }

    @Test
    fun canStoreEmptyString() {

        val key = "some empty-string key"
        val value = ""

        prefs.edit().putString(key, value).apply()

        assertEquals(value, prefs.getString(key, "not what I want"))
    }

    @Test
    fun canStoreEmptyStringSet() {

        val key = "some empty-string-set key"
        val value = setOf<String>(/*nothing*/)

        prefs.edit().putStringSet(key, value).apply()

        assertEquals(value, prefs.getStringSet(key, null))
    }

    @Test
    fun canStoreStringSetWithEmptyString() {

        val key = "some string-set key for blanks"
        val value = setOf("")

        prefs.edit().putStringSet(key, value).apply()

        assertEquals(value, prefs.getStringSet(key, null))
    }

    @Test
    fun getInt() {

        val key = "some int key"
        val value = 42

        prefs.edit().putInt(key, value).apply()

        assertEquals(value, prefs.getInt(key, value + 1))
    }

    @Test
    fun getLong() {

        val key = "some long key"
        val value = 42L

        prefs.edit().putLong(key, value).apply()

        assertEquals(value, prefs.getLong(key, value + 1))
    }

    @Test
    fun getFloat() {

        val key = "some float key"
        val value = 42.0f

        prefs.edit().putFloat(key, value).apply()

        assertEquals(value, prefs.getFloat(key, value + 3.14f))
    }

    @Test
    fun getStringSet() {

        val key = "some string set key"
        val value = setOf("one", "two", "three")

        prefs.edit().putStringSet(key, value).apply()

        assertEquals(value, prefs.getStringSet(key, null))
    }

    @Test
    fun getBoolean() {
        val key = "some bool key"

        prefs.edit().putBoolean(key, true).apply()

        assertTrue(prefs.getBoolean(key, false))
    }

    @Test
    fun clear() {
        prefs.edit().clear().apply()

        assertTrue(prefs.all.isEmpty())

    }

    @Test
    fun all() {

        prefs.edit().clear().apply()

        prefs.edit()
                .putBoolean("b", true)
                .putString("s", "hello")
                .putFloat("f", 3.14f)
                .putLong("l", 42L)
                .putInt("i", 43)
                .putStringSet("set", setOf("hello", "world", "!"))
                .apply()

        assertTrue(prefs.all.containsKey("b"))
        assertTrue(prefs.all.containsKey("s"))
        assertTrue(prefs.all.containsKey("f"))
        assertTrue(prefs.all.containsKey("l"))
        assertTrue(prefs.all.containsKey("i"))
        assertTrue(prefs.all.containsKey("set"))

        assertTrue(prefs.all.containsValue(true))
        assertTrue(prefs.all.containsValue("hello"))
        assertTrue(prefs.all.containsValue(3.14f))
        assertTrue(prefs.all.containsValue(42L))
        assertTrue(prefs.all.containsValue(43))
        assertTrue(prefs.all.containsValue(setOf("hello", "world", "!")))

    }

    @Test
    fun remove() {
        prefs.edit()
                .putString("key", "value")
                .apply()

        prefs.edit().remove("key").apply()

        assertFalse(prefs.contains("key"))

    }

    @Test
    fun commitSameAsApply() {
        prefs.edit()
                .clear()
                .putString("key", "value")
                .putInt("key_i", 12)
                .putBoolean("key_b", true)
                .apply()

        val asApplied = prefs.all

        prefs.edit()
                .clear()
                .putString("key", "value")
                .putInt("key_i", 12)
                .putBoolean("key_b", true)
                .commit()

        val asCommitted = prefs.all

        assertEquals(asApplied, asCommitted)

    }

    @Test
    fun encryptionVaries() {
        val basePrefs = prefs.delegate

        val value = "some string"

        prefs.edit()
                .putString("first", value)
                .putString("second", value)
                .apply()

        val readFirst = basePrefs.getString("s:first", "same")
        val readSecond = basePrefs.getString("s:second", "same")

        assertNotEquals(readFirst, readSecond)
    }

    @Test
    fun clearsUnencryptedData() {
        val originalPrefs = InstrumentationRegistry.getContext().getSharedPreferences("dummy", MODE_PRIVATE)
        originalPrefs.edit()
                .putBoolean("b_bla", true)
                .putString("s_bla", "hello")
                .putFloat("f_bla", 3.14f)
                .putLong("l_bla", 42L)
                .putInt("i_bla", 43)
                .putStringSet("set_bla", setOf("hello", "world", "!"))
                .apply()

        val wrappedPrefs = ProtectedSharedPreferences(originalPrefs)

        setOf("b", "s", "f", "l", "i", "set").forEach {
            assertFalse(originalPrefs.contains("${it}_bla"))
            assertTrue("was looking for key ${it}_bla but did not find it", wrappedPrefs.contains("${it}_bla"))
        }
    }


    @Test
    fun clearsUnreadableDataOnContains() {
        val originalPrefs = InstrumentationRegistry.getContext().getSharedPreferences("unreadable", MODE_PRIVATE)

        val wrappedPrefs = ProtectedSharedPreferences(originalPrefs)

        //force some prefix collisions to make decryption fail
        originalPrefs.edit()
                .putBoolean("b:b_bla", true)
                .putString("s:s_bla", "hello")
                .putFloat("f:f_bla", 3.14f)
                .putLong("l:l_bla", 42L)
                .putInt("i:i_bla", 43)
                .putStringSet("e:set_bla", setOf("hello", "world", "!"))
                .apply()

        setOf("b", "s", "f", "l", "i", "set").forEach {

            assertFalse(wrappedPrefs.contains("${it}_bla"))

        }

        //the unreadable prefs should have been cleared by the above calls
        assertTrue(originalPrefs.all.isEmpty())
        assertTrue(wrappedPrefs.all.isEmpty())
    }

    @Test
    fun returnsDefaultsWhenDecryptionFails() {
        val originalPrefs = InstrumentationRegistry.getContext().getSharedPreferences("defaultable", MODE_PRIVATE)

        val wrappedPrefs = ProtectedSharedPreferences(originalPrefs)

        //force some prefix collisions to make decryption fail
        originalPrefs.edit()
                .putBoolean("b:b_bla", true)
                .putString("s:s_bla", "hello")
                .putFloat("f:f_bla", 3.14f)
                .putLong("l:l_bla", 42L)
                .putInt("i:i_bla", 43)
                .putStringSet("e:set_bla", setOf("hello", "world", "!"))
                .apply()

        assertEquals(false, wrappedPrefs.getBoolean("b_bla", false))
        assertEquals("goodbye", wrappedPrefs.getString("s_bla", "goodbye"))
        assertEquals(6.28f, wrappedPrefs.getFloat("f_bla", 6.28f))
        assertEquals(-942L, wrappedPrefs.getLong("l_bla", -942L))
        assertEquals(-943, wrappedPrefs.getInt("i_bla", -943))
        assertEquals(setOf("goodbye", "world"), wrappedPrefs.getStringSet("set_bla", setOf("goodbye", "world").toMutableSet()))

        //the unreadable prefs should have been cleared by the above calls
        assertTrue(originalPrefs.all.isEmpty())
        assertTrue(wrappedPrefs.all.isEmpty())
    }

    @Test
    fun canOverwriteData() {

        val key = "myKey"
        val value = setOf("hello", "world")
        prefs.edit().putStringSet(key, value).apply()
        assertEquals(value, prefs.getStringSet(key, null))

        val newValue = setOf("goodbye", "worlds")
        prefs.edit().putStringSet(key, newValue).apply()
        assertEquals(newValue, prefs.getStringSet(key, null))
    }

    @Test
    fun canOverwriteDataAndType() {

        val key = "myKey"
        val value = setOf("hello", "world")
        prefs.edit().putStringSet(key, value).apply()
        assertEquals(value, prefs.getStringSet(key, null))

        val newValue = 42.0f
        prefs.edit().putFloat(key, newValue).apply()
        assertEquals(newValue, prefs.getFloat(key, 3.14f))
    }

    @Test
    fun readsDefaultsWhenDatatypeMismatch() {

        val key = "myKey"
        val value = setOf("hello", "world")
        prefs.edit().putStringSet(key, value).apply()
        assertEquals(value, prefs.getStringSet(key, null))

        assertEquals("whatever", prefs.getString(key, "whatever"))
    }
}
using System;
using System.Collections.Generic;
using NUnit.Framework;
using MasterCard.Core.Model;


namespace TestMasterCard
{
	[TestFixture ()]
	public class BaseMapTest
	{
		[Test ()]
		public void TestAdd(){
			RequestMap map = new RequestMap ();
			map.Add("key1", "value1");

			Assert.AreEqual (1, map.Count);
			Assert.IsTrue(map.ContainsKey("key1"));
			Assert.AreEqual ("value1", map ["key1"]);

			//test negative
			Assert.IsFalse(map.ContainsKey("key2"));

		}


		[Test ()]
		public void TestAddWithConstructor(){
			RequestMap map = new RequestMap ("key1", "value1");

			Assert.AreEqual (1, map.Count);
			Assert.IsTrue(map.ContainsKey("key1"));
			Assert.AreEqual ("value1", map ["key1"]);

			//test negative
			Assert.IsFalse(map.ContainsKey("key2"));

		}

		[Test ()]
		public void TestNestedAdd(){
			RequestMap map = new RequestMap ();
			map.Add("key1.key2", "value1");

			Assert.AreEqual (1, map.Count);
			Assert.IsTrue(map.ContainsKey("key1"));
			Assert.IsTrue(map.ContainsKey("key1.key2"));
			Assert.AreEqual ("value1", map ["key1.key2"]);
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map["key1"]).Count);

			//test negative
			Assert.IsFalse(map.ContainsKey("key2"));
			Assert.IsFalse (map.ContainsKey ("key2.key1"));

		}


		[Test()]
		public void TestIssueWithMockResponse() {
			String responseString = "{  \n" + "   \"website\":\"hildegard.org\",\n" + "   \"address\":{  \n"
			                         + "      \"instructions\":{  \n" + "         \"doorman\":true,\n"
			                         + "         \"text\":\"some delivery instructions text\"\n" + "      },\n"
			                         + "      \"city\":\"New York\",\n" + "      \"postalCode\":\"10577\",\n" + "      \"id\":1,\n"
			                         + "      \"state\":\"NY\",\n" + "      \"line1\":\"2000 Purchase Street\"\n" + "   },\n"
			                         + "   \"phone\":\"1-770-736-8031\",\n" + "   \"name\":\"Joe Bloggs\",\n" + "   \"id\":1,\n"
			                         + "   \"email\":\"name@example.com\",\n" + "   \"username\":\"jbloggs\"\n" + "}";

			RequestMap tmpMap = new RequestMap (responseString);
			Assert.AreEqual ("hildegard.org", tmpMap ["website"]);	
			Assert.AreEqual ("some delivery instructions text", tmpMap ["address.instructions.text"]);	
			Assert.AreEqual ("true", tmpMap ["address.instructions.doorman"].ToString().ToLower());	

		}


		[Test()]
		public void TestIssueWithMockResponseAsDictionary() {
			String responseString = "{  \n" + "   \"website\":\"hildegard.org\",\n" + "   \"address\":{  \n"
				+ "      \"instructions\":{  \n" + "         \"doorman\":true,\n"
				+ "         \"text\":\"some delivery instructions text\"\n" + "      },\n"
				+ "      \"city\":\"New York\",\n" + "      \"postalCode\":\"10577\",\n" + "      \"id\":1,\n"
				+ "      \"state\":\"NY\",\n" + "      \"line1\":\"2000 Purchase Street\"\n" + "   },\n"
				+ "   \"phone\":\"1-770-736-8031\",\n" + "   \"name\":\"Joe Bloggs\",\n" + "   \"id\":1,\n"
				+ "   \"email\":\"name@example.com\",\n" + "   \"username\":\"jbloggs\"\n" + "}";

			RequestMap tmpMap = new RequestMap (RequestMap.AsDictionary(responseString));
			Assert.AreEqual ("hildegard.org", tmpMap ["website"]);	
			Assert.AreEqual ("some delivery instructions text", tmpMap ["address.instructions.text"]);	
			Assert.AreEqual ("true", tmpMap ["address.instructions.doorman"].ToString().ToLower());	

		}


		[Test ()]
		public void TestRemve(){
			RequestMap map = new RequestMap ();
			map.Add("key1", "value1");

			Assert.AreEqual (1, map.Count);
			Assert.IsTrue(map.ContainsKey("key1"));
			Assert.AreEqual ("value1", map ["key1"]);

			//test negative
			Assert.IsFalse(map.ContainsKey("key2"));

			map.Remove ("key1");
			Assert.AreEqual (0, map.Count);
			Assert.IsFalse(map.ContainsKey("key1"));


		}


		[Test ()]
		public void TestReplace(){
			RequestMap map = new RequestMap ();
			map.Add("key1.key2", "value1");

			Assert.AreEqual (1, map.Count);
			//checl is it finds the key
			Assert.IsTrue(map.ContainsKey("key1"));
			//check if it find the nested keys
			Assert.IsTrue(map.ContainsKey("key1.key2"));
			// check if it find returns the correct value
			Assert.AreEqual ("value1", map ["key1.key2"]);
			// check if the first level map contains only one value
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map["key1"]).Count);


			map.Add("key1.key2", "value2");

			Assert.AreEqual (1, map.Count);
			//checl is it finds the key
			Assert.IsTrue(map.ContainsKey("key1"));
			//check if it find the nested keys
			Assert.IsTrue(map.ContainsKey("key1.key2"));
			// check if it find returns the correct value
			Assert.AreEqual ("value2", map ["key1.key2"]);
			// check if the first level map contains only one value
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map["key1"]).Count);
		}


		[Test ()]
		public void TesNestedAdd(){
			RequestMap map = new RequestMap ();
			map.Add("key1.key1", "value1");

			Assert.AreEqual (1, map.Count);
			//checl is it finds the key
			Assert.IsTrue(map.ContainsKey("key1"));
			//check if it find the nested keys
			Assert.IsTrue(map.ContainsKey("key1.key1"));
			// check if it find returns the correct value
			Assert.AreEqual ("value1", map ["key1.key1"]);
			// check if the first level map contains only one value
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map["key1"]).Count);


			map.Add("key1.key2", "value2");

			Assert.AreEqual (1, map.Count);
			//checl is it finds the key
			Assert.IsTrue(map.ContainsKey("key1"));
			//check if it find the nested keys
			Assert.IsTrue(map.ContainsKey("key1.key2"));
			// check if it find returns the correct value
			Assert.AreEqual ("value2", map ["key1.key2"]);
			// check if the first level map contains only one value
			Assert.AreNotSame(2, ((Dictionary<String,Object>) map["key1"]).Count);


		}


		[Test ()]
		public void TestConvertValueToMap()	{
			RequestMap map = new RequestMap ();
			map.Add("level1", "value1");
			Assert.Throws<ArgumentException> (()=> { map.Add ("level1.level2", "level2");} );

		}


		[Test ()]
		public void TestMultipleAdd4Deep(){
			RequestMap map = new RequestMap ();
			map.Add("key1.key2.key3.key4", "value1");

			Assert.AreEqual (1, map.Count);
			//checl is it finds the key
			Assert.IsTrue(map.ContainsKey("key1"));
			Assert.IsTrue(map.ContainsKey("key1.key2"));
			Assert.IsTrue(map.ContainsKey("key1.key2.key3"));
			Assert.IsTrue(map.ContainsKey("key1.key2.key3.key4"));

			// check if it find returns the correct value
			Assert.AreEqual ("value1", map ["key1.key2.key3.key4"]);
			// check if the first level map contains only one value
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map["key1.key2.key3"]).Count);
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map["key1.key2"]).Count);
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map["key1"]).Count);

		}


		[Test ()]
		public void TestAdd4List(){
			RequestMap map = new RequestMap ();
			map.Add("key1", new List<String>() { "value1", "value2", "value3" });

			Assert.IsTrue(map.ContainsKey("key1"));
			Assert.AreEqual (3, ((List<String>) map ["key1"]).Count);

		}



		[Test ()]
		public void TestAddIndexed(){
			RequestMap map = new RequestMap ();
			map.Add("map[].name", "name1");
			map.Add("map[].name", "name2");
			map.Add("map[].name", "name3");

			Assert.AreEqual (1, map.Count);

			Assert.AreNotSame(1, ((List<IDictionary<String, Object>> ) map["map"]).Count); 
			//checl is it finds the key
			Assert.IsTrue(map.ContainsKey("map"));
			Assert.IsTrue(map.ContainsKey("map[0]"));
			Assert.IsTrue(map.ContainsKey("map[1]"));
			Assert.IsTrue(map.ContainsKey("map[2]"));
			Assert.IsFalse(map.ContainsKey("map[3]"));


			Assert.AreEqual ("name1", map ["map[0].name"]);
			Assert.AreEqual ("name2", map ["map[1].name"]);
			Assert.AreEqual ("name3", map ["map[2].name"]);

			// check if the first level map contains only one value
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map ["map[0]"]).Count);
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map ["map[1]"]).Count);
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map ["map[2]"]).Count);

		}

		[Test ()]
		public void TestConstructorDictionary(){

			Dictionary<String,Object> testDictionary = new Dictionary<string, object> ();
			testDictionary.Add ("boolean", true);
			testDictionary.Add ("double", 0.5);
			testDictionary.Add ("long", 1000);
			testDictionary.Add ("int", 16);
			testDictionary.Add ("list", new List<String>() {"one", "one", "one"});
			testDictionary.Add ("map", new Dictionary<String, String>() { {"0","one"}, { "1","one"}, {"2","one"}});

			RequestMap map = new RequestMap (testDictionary);

			Assert.AreEqual (6, map.Count);
			Assert.IsTrue(map.ContainsKey("boolean"));
			Assert.IsTrue(map.ContainsKey("double"));
			Assert.IsTrue(map.ContainsKey("long"));
			Assert.IsTrue(map.ContainsKey("int"));
			Assert.IsTrue(map.ContainsKey("list"));
			Assert.IsTrue(map.ContainsKey("map"));

			Assert.AreEqual (true, map ["boolean"]);
			Assert.AreEqual (0.5, map ["double"]);
			Assert.AreEqual (1000, map ["long"]);
			Assert.AreEqual (16, map ["int"]);
			Assert.AreEqual (3, ((List<String>) map ["list"]).Count);
			Assert.AreEqual (3, ((Dictionary<String, String>) map ["map"]).Count);

		}

		[Test ()]
		public void TestConstructorBaseMap(){
			RequestMap map = new RequestMap ();
			map.Add("map[].name", "name1");
			map.Add("map[].name", "name2");
			map.Add("map[].name", "name3");

			Assert.AreEqual (1, map.Count);

			Assert.AreNotSame(1, ((List<IDictionary<String, Object>> ) map["map"]).Count); 
			//checl is it finds the key
			Assert.IsTrue(map.ContainsKey("map"));
			Assert.IsTrue(map.ContainsKey("map[0]"));
			Assert.IsTrue(map.ContainsKey("map[1]"));
			Assert.IsTrue(map.ContainsKey("map[2]"));
			Assert.IsFalse(map.ContainsKey("map[3]"));


			Assert.AreEqual ("name1", map ["map[0].name"]);
			Assert.AreEqual ("name2", map ["map[1].name"]);
			Assert.AreEqual ("name3", map ["map[2].name"]);

			// check if the first level map contains only one value
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map ["map[0]"]).Count);
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map ["map[1]"]).Count);
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map ["map[2]"]).Count);

			RequestMap newMap = new RequestMap (map);

			Assert.AreEqual (1, newMap.Count);

			Assert.AreNotSame(1, ((List<IDictionary<String, Object>> ) newMap["map"]).Count); 
			//checl is it finds the key
			Assert.IsTrue(newMap.ContainsKey("map"));
			Assert.IsTrue(newMap.ContainsKey("map[0]"));
			Assert.IsTrue(newMap.ContainsKey("map[1]"));
			Assert.IsTrue(newMap.ContainsKey("map[2]"));
			Assert.IsFalse(newMap.ContainsKey("map[3]"));


			Assert.AreEqual ("name1", newMap ["map[0].name"]);
			Assert.AreEqual ("name2", newMap ["map[1].name"]);
			Assert.AreEqual ("name3", newMap ["map[2].name"]);

			// check if the first level map contains only one value
			Assert.AreNotSame(1, ((Dictionary<String,Object>) newMap ["map[0]"]).Count);
			Assert.AreNotSame(1, ((Dictionary<String,Object>) newMap ["map[1]"]).Count);
			Assert.AreNotSame(1, ((Dictionary<String,Object>) newMap ["map[2]"]).Count);


		}



		[Test ()]
		public void TestReplaceIndexed(){
			RequestMap map = new RequestMap ();
			map.Add("map[].name", "name1");

			Assert.AreEqual (1, map.Count);

			Assert.AreNotSame(1, ((List<IDictionary<String, Object>> ) map["map"]).Count); 
			//checl is it finds the key
			Assert.AreEqual ("name1", map ["map[0].name"]);

			// check if the first level map contains only one value
			Assert.AreNotSame(1, ((Dictionary<String,Object>) map ["map[0]"]).Count);


			map.Add("map[0].name", "name1_replaced");
			map.Add("map[0].surname", "surname");

			Assert.AreNotSame(2, ((List<IDictionary<String, Object>> ) map["map"]).Count); 

			Assert.AreEqual ("name1_replaced", map ["map[0].name"]);
			Assert.AreEqual ("surname", map ["map[0].surname"]);


		}


		[Test ()]
		public void TestAddIndexedWithOffset(){
			RequestMap map = new RequestMap ();



			Assert.Throws<ArgumentOutOfRangeException> (()=> { map.Add("map[1].name", "name1"); });



		}


		[Test ()]
		public void TestAddAll(){
			RequestMap map = new RequestMap ();

			Dictionary<String, Object> tmpDict = new Dictionary<String,Object> ();
			tmpDict.Add ("user.name", "andrea");
			tmpDict.Add ("user.surname", "rizzini");

			map.AddAll (tmpDict);

			Assert.AreEqual (1, map.Count);

			Assert.IsTrue(map.ContainsKey("user"));
			Assert.IsTrue(map.ContainsKey("user.name"));
			Assert.IsTrue(map.ContainsKey("user.surname"));

			Assert.AreEqual ("andrea", map ["user.name"]);
			Assert.AreEqual ("rizzini", map ["user.surname"]);

		}

		[Test ()]
		public void TestAddAllAsConstructor(){
			

			Dictionary<String, Object> tmpDict = new Dictionary<String,Object> ();
			tmpDict.Add ("user.name", "andrea");
			tmpDict.Add ("user.surname", "rizzini");

			RequestMap map = new RequestMap (tmpDict);

			Assert.AreEqual (1, map.Count);

			Assert.IsTrue(map.ContainsKey("user"));
			Assert.IsTrue(map.ContainsKey("user.name"));
			Assert.IsTrue(map.ContainsKey("user.surname"));

			Assert.AreEqual ("andrea", map ["user.name"]);
			Assert.AreEqual ("rizzini", map ["user.surname"]);

		}


		[Test ()]
		public void TestJson(){

			String tmpDict = " { \"user.name\":\"andrea\", \"user.surname\":\"rizzini\" }";

			RequestMap map = new RequestMap (tmpDict);

			Assert.AreEqual (1, map.Count);

			Assert.IsTrue(map.ContainsKey("user"));
			Assert.IsTrue(map.ContainsKey("user.name"));
			Assert.IsTrue(map.ContainsKey("user.surname"));

			Assert.AreEqual ("andrea", map ["user.name"]);
			Assert.AreEqual ("rizzini", map ["user.surname"]);
		}


		[Test ()]
		public void TestJson2(){

			String tmpDict = "{\n  \"mapName\": \"name\",\n  \"list\": [\n    {\n      \"itemId\": 1,\n      \"name\": \"name\",\n      \"list\": [\n         1, 2, 3, 4  \n      ]\n    },\n    {\n      \"itemId\": 2,\n      \"name\": \"name\",\n      \"list\": [\n         1, 2, 3, 4  \n      ]\n    },\n    {\n      \"itemId\": 3,\n      \"name\": \"name\",\n      \"list\": [\n         1, 2, 3, 4  \n      ]\n    }\n  ]\n}";

			IDictionary<String,Object> dict = RequestMap.AsDictionary(tmpDict);
			Assert.IsTrue (dict.ContainsKey ("mapName"));
			Assert.IsTrue (dict.ContainsKey ("list"));

			Assert.AreSame (typeof(List<Dictionary<String, Object>>), dict ["list"].GetType());

		}


	}



}


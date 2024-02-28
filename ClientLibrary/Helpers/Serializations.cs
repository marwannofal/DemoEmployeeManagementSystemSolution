
using System.Text.Json;
using BaseLibrary.DTOs;

namespace ClientLibrary.Helpers
{
    public static class Serializations
    {
        public static string SerialzeObj<T>(T modelObject) => JsonSerializer.Serialize(modelObject);
        public static T DeserializeJsonString<T>(string jsonString) => JsonSerializer.Deserialize<T>(jsonString);

        public static IList<T> DeserializeJsonStringList<T>(string jsonString) =>
            JsonSerializer.Deserialize<IList<T>>(jsonString);
    }
}

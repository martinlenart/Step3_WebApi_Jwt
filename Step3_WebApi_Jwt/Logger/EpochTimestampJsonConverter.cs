using System;
using Newtonsoft.Json;

namespace Step3_WebApi_WebApi.Logger
{
    public sealed class EpochTimestampJsonConverter : JsonConverter
    {
        private static readonly DateTimeOffset Epoch = new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero);

        public override bool CanConvert(Type objectType) => objectType == typeof(DateTimeOffset);

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            if (value != null)
            {
                var dto = (DateTimeOffset)value;
                var delta = dto - Epoch;
                writer.WriteValue((long)delta.TotalMilliseconds);
            }
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            var ticks = (long?)reader.Value;
            if (!ticks.HasValue)
            {
                return null;
            }
            return Epoch.AddMilliseconds(ticks.Value);
        }
    }
}

namespace Poort8.Ishare.Core.Models;

[Serializable]
public class SatelliteException : Exception
{
    public SatelliteException()
    {
    }

    public SatelliteException(string message) : base("Satellite exception - " + message)
    {
    }

    public SatelliteException(string message, Exception? innerException) : base("Satellite exception - " + message, innerException)
    {
    }
}
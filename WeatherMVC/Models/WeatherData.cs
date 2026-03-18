namespace WeatherMVC.Models;

public record WeatherData(DateTime Date, int TemperatureC, int TemperatureF, string Summary);
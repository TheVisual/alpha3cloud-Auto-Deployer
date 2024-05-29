class Program
{
    static async Task Main()
    {
        Console.Write("Enter the number of threads to use: ");

        // Parse the user input and validate it
        if (!int.TryParse(Console.ReadLine(), out int threadCount) || threadCount <= 0)
        {
            Console.WriteLine("Invalid input. Please enter a valid number of threads.");
            return;
        }

        try
        {
            // Semaphore to limit the number of concurrent tasks
            SemaphoreSlim semaphore = new SemaphoreSlim(threadCount);

            // This function performs the required operation
            async Task ExecuteProcessAsync(int index)
            {
                await semaphore.WaitAsync();
                try
                {
                    await Task.Run(async () => 
                    {
                        var captchaKey = await MethodsExensions.SolveCaptchaSJC();
                        Console.WriteLine(captchaKey);
                        if (!string.IsNullOrEmpty(captchaKey))
                        {
                            await MethodsExensions.DeploySSHSJC(captchaKey);
                        }
                    });
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"An error occurred: {ex.Message}");

                }
                finally
                {
                    // Release the semaphore so another task can start
                    semaphore.Release();
                }
            }

            Console.Write("Enter the number of bots to create: ");

            // Parse the user input and validate it
            if (!int.TryParse(Console.ReadLine(), out int botCount) || botCount <= 0)
            {
                Console.WriteLine("Invalid input. Please enter a valid number of accounts.");
                return;
            }

            // Start all the tasks
            var tasks = Enumerable.Range(1, botCount).Select(ExecuteProcessAsync).ToArray();

            // Wait for all the tasks to complete
            await Task.WhenAll(tasks);

            Console.WriteLine("All tasks completed.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An unexpected error occurred: {ex.Message}");
        }

        Console.ReadLine();
    }
}
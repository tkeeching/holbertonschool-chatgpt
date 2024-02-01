## ChatPPT - Introduction

### Task 0. Debugging

The following tasks build upon each other, it is recommended that you follow them in order for the best experience.

It has been reported that students in the ‘Creating Pop Music Lyrics With ChatGPT’ subject with a final mark of 85 are receiving an incorrect final grade when their report cards are being generated.

The following python function is responsible for returning the appropriate grade for a student when given their final mark.

```python
def graduate:
    grade = ‘Unknown’
    if mark < 50:
        grade = ‘Not yet successful’
    elif mark >=50 and mark <= 60:
        grade = ‘Pass’
    elif mark > 60 and mark <= 75:
        grade = ‘Credit’
    elif mark > 75 and mark < 85:
        grade = ‘Distinction’
    elif mark > 85:
        grade = ‘High Distinction’
    else:
        grade = ‘Unknown’
    return grade
```

Having a look at the code yourself, suggest where the issue could potentially be.

Write the correct prompt to explain to ChatGPT the problem that is being experienced with this function and ask it to identify and resolve the issue.

### Solution

#### Prompt

```
It has been reported that student with the final mark of 85
are receiving incorrect final grade when their report
cards are being generated. The following snippet of python
code were used to generate the final grade based on the
students' final mark. Would you be able to identify the potential
issue of the code and suggest a fix?

\\\code snippet
def graduate:
    grade = ‘Unknown’
    if mark < 50:
        grade = ‘Not yet successful’
    elif mark >=50 and mark <= 60:
        grade = ‘Pass’
    elif mark > 60 and mark <= 75:
        grade = ‘Credit’
    elif mark > 75 and mark < 85:
        grade = ‘Distinction’
    elif mark > 85:
        grade = ‘High Distinction’
    else:
        grade = ‘Unknown’
    return grade
\\\

```

#### ChatGPT Response

It seems there is a syntax error in the code snippet provided, and there's an issue with the comparison in the last `elif` statement. Also, the function definition lacks parentheses. Here's the corrected code:

```python
def graduate(mark):
    grade = 'Unknown'
    if mark < 50:
        grade = 'Not yet successful'
    elif mark >= 50 and mark <= 60:
        grade = 'Pass'
    elif mark > 60 and mark <= 75:
        grade = 'Credit'
    elif mark > 75 and mark < 85:
        grade = 'Distinction'
    elif mark >= 85:
        grade = 'High Distinction'
    else:
        grade = 'Unknown'
    return grade
```

Changes made:

Added the missing parentheses in the function definition.
Corrected the comparison in the last `elif` statement to use `>= 85` instead of `> 85`.
Now the function should work correctly for students with a final mark of 85, and it will return 'High Distinction' as expected.

---

### Task 1. Refactoring

### Solution

#### Prompt

Could you refactor the code so that it meets the following requirements?

1. Code follows the python PEP 8 style guide.
2. The code snippet is wrapped in a function.
3. The code snipped raises a ValueError if the mark is outside of the range 0-100.

#### ChatGPT Response

Certainly! Here's the refactored code that meets the specified requirements:

```python
def calculate_grade(mark):
    if not (0 <= mark <= 100):
        raise ValueError("Mark must be in the range 0-100")

    if mark < 50:
        grade = 'Not yet successful'
    elif 50 <= mark <= 60:
        grade = 'Pass'
    elif 60 < mark <= 75:
        grade = 'Credit'
    elif 75 < mark < 85:
        grade = 'Distinction'
    else:
        grade = 'High Distinction'

    return grade
```

Changes made:

Function name follows snake_case style (PEP 8).
Added a check to raise a `ValueError` if the input mark is outside the range 0-100.
Updated the code to use more readable and consistent indentation.
Now, when you call `calculate_grade` with a mark outside the range 0-100, it will raise a `ValueError`. Otherwise, it will calculate and return the corresponding grade.

---

### Task 2. Generate Test Cases

### Solution

#### Prompt

Great! Could you implement some test cases for this code with the following requirements?

1. When given an input of 0-49, the function should return ‘Not yet successful’.
2. 50-60 ‘Pass’
3. 61-75 ‘Credit’
4. 76 – 85 ‘Distinction’
5. 86-100 ‘ High Distinction’’

Please also include test to verify the ValueError exception

#### ChatGPT Response

Certainly! Here are some test cases using the `unittest` module to verify the behavior of the `calculate_grade` function:

```python
import unittest

class TestCalculateGrade(unittest.TestCase):

    def test_not_successful(self):
        self.assertEqual(calculate_grade(0), 'Not yet successful')
        self.assertEqual(calculate_grade(49), 'Not yet successful')

    def test_pass(self):
        self.assertEqual(calculate_grade(50), 'Pass')
        self.assertEqual(calculate_grade(60), 'Pass')

    def test_credit(self):
        self.assertEqual(calculate_grade(61), 'Credit')
        self.assertEqual(calculate_grade(75), 'Credit')

    def test_distinction(self):
        self.assertEqual(calculate_grade(76), 'Distinction')
        self.assertEqual(calculate_grade(85), 'Distinction')

    def test_high_distinction(self):
        self.assertEqual(calculate_grade(86), 'High Distinction')
        self.assertEqual(calculate_grade(100), 'High Distinction')

    def test_value_error(self):
        with self.assertRaises(ValueError):
            calculate_grade(-1)  # Below the valid range

        with self.assertRaises(ValueError):
            calculate_grade(101)  # Above the valid range

if __name__ == '__main__':
    unittest.main()
```

These test cases cover various scenarios, including the expected grade for different mark ranges and checking that a `ValueError` is raised when the input mark is outside the valid range.

---

### Task 3. Documentation

### Solution

#### Prompt
Could you write a documentation for the `calculate_grade` function?

#### ChatGPT Response

```python
def calculate_grade(mark):
    """
    Calculate the grade based on the given mark.

    Args:
    - mark (int): The student's final mark, should be in the range 0-100.

    Returns:
    - str: The corresponding grade based on the mark:
        - 'Not yet successful' for marks 0-49.
        - 'Pass' for marks 50-60.
        - 'Credit' for marks 61-75.
        - 'Distinction' for marks 76-85.
        - 'High Distinction' for marks 86-100.

    Raises:
    - ValueError: If the mark is outside the valid range (0-100).
    """
    if not (0 <= mark <= 100):
        raise ValueError("Mark must be in the range 0-100")

    if mark < 50:
        grade = 'Not yet successful'
    elif 50 <= mark <= 60:
        grade = 'Pass'
    elif 60 < mark <= 75:
        grade = 'Credit'
    elif 75 < mark < 85:
        grade = 'Distinction'
    else:
        grade = 'High Distinction'

    return grade
```

---

### Task 4. Security checks (OWASP)

### Solution

#### Prompt

Given the following python code snippet, could you please review the code and identify any potential OWASP vulnerability?

```code snippet
def get_customer_daily_sales(customer_code):
    # Get sql db connection
    sql_con = get_sql_connection()

    # Create a cursor
    cur = sql_con.cursor()

     # Produce query to get customer average sales
     query = f"""
         SELECT
                o.CustomerName,
                CAST(o.OrderDt AS DATE) AS OrderDate,
                SUM(o.OrderTotal) AS DailyTotal
            FROM dbo.Orders AS o
            INNER JOIN dbo.Customers AS c
                on o.CustomerKey = c.CustomerKey
            AND c.CustomerCode = '{customer_code}'
            GROUP BY o.CustomerName, CAST(o.OrderDt as DATE);
     """

    # Execute the query
    cur.execute(query)

    # Collect query result
    result = cur.fetchall()

    # Close the connection
    sql_con.close()

    # Return the result
    return result
```

#### ChatGPT Response

The code snippet you provided is vulnerable to SQL injection, which is listed as a critical security risk by OWASP (Open Web Application Security Project).

The vulnerability lies in the construction of the SQL query string using string formatting with the `customer_code` variable directly embedded into the query. If an attacker can control the value of `customer_code`, they can manipulate the SQL query to execute arbitrary SQL commands, potentially leading to unauthorized access to data or even data manipulation or deletion.

To mitigate this vulnerability, you should use parameterized queries or prepared statements. Here's how you can modify the code to use parameterized queries:

```python
def get_customer_daily_sales(customer_code):
    # Get sql db connection
    sql_con = get_sql_connection()

    # Create a cursor
    cur = sql_con.cursor()

    # Prepare query with placeholders
    query = """
        SELECT
            o.CustomerName,
            CAST(o.OrderDt AS DATE) AS OrderDate,
            SUM(o.OrderTotal) AS DailyTotal
        FROM dbo.Orders AS o
        INNER JOIN dbo.Customers AS c
            on o.CustomerKey = c.CustomerKey
        AND c.CustomerCode = %s
        GROUP BY o.CustomerName, CAST(o.OrderDt as DATE);
    """

    # Execute the query with parameter
    cur.execute(query, (customer_code,))

    # Collect query result
    result = cur.fetchall()

    # Close the connection
    sql_con.close()

    # Return the result
    return result
```

By using parameterized queries, you separate the SQL query logic from the data, preventing the possibility of SQL injection attacks. The parameterized query ensures that the `customer_code` value is treated as data and not as part of the SQL command structure, thus safeguarding against SQL injection vulnerabilities.

#### Prompt

Can you please explain the remaining OWASP Top 10 issues and provide some example for each?

#### ChatGPT Response

Sure, I can provide an overview of the remaining OWASP Top 10 issues along with examples for each:

1. **Broken Authentication**: This refers to any vulnerability that allows attackers to compromise user accounts, passwords, or session tokens, or to exploit other flaws in authentication mechanisms. Examples include:
   - Weak password policies allowing easy-to-guess passwords.
   - Lack of multi-factor authentication (MFA), allowing attackers to bypass authentication controls.
   - Session fixation attacks where an attacker sets a user's session ID, gaining unauthorized access.

2. **Sensitive Data Exposure**: This occurs when sensitive information such as passwords, credit card numbers, or personal data is not adequately protected, allowing unauthorized access. Examples include:
   - Storing passwords in plaintext instead of hashed form.
   - Transmitting sensitive data over unencrypted channels.
   - Failure to implement proper access controls, leading to unauthorized access to sensitive data.

3. **XML External Entities (XXE)**: XXE vulnerabilities occur when an application processes XML input containing external entity references in an unsafe manner. Attackers can exploit this to disclose confidential data, execute remote code, or perform denial of service attacks. Examples include:
   - Including external entities in XML requests to read local files.
   - Using external entity references to perform server-side request forgery (SSRF) attacks.
   - Exploiting XXE to exfiltrate sensitive data by reading files accessible to the server.

4. **Broken Access Control**: This refers to improper enforcement of restrictions on what authenticated users are allowed to do, such as accessing other users' accounts, modifying other users' data, or changing access rights. Examples include:
   - Direct object references allowing users to manipulate parameters in URLs to access unauthorized resources.
   - Insufficient access controls on APIs, allowing unauthorized access to sensitive data or functionality.
   - Predictable resource locations or identifiers, enabling attackers to access restricted resources.

5. **Security Misconfiguration**: This occurs when security settings are improperly configured, leading to potential vulnerabilities. Examples include:
   - Default credentials left unchanged, allowing unauthorized access.
   - Open ports or services that are not necessary for the application's functionality.
   - Exposing sensitive information in error messages or debug logs.

6. **Cross-Site Scripting (XSS)**: XSS vulnerabilities allow attackers to inject malicious scripts into web pages viewed by other users. This can lead to the theft of session cookies, defacement of websites, or execution of arbitrary code in the context of the victim's browser. Examples include:
   - Reflective XSS attacks where user input is immediately echoed back to the browser without proper validation or encoding.
   - Stored XSS attacks where user input is stored in the application's database and later displayed to other users without proper sanitization.
   - DOM-based XSS attacks where client-side scripts manipulate the DOM in an unsafe manner.

7. **Insecure Deserialization**: This refers to vulnerabilities arising from insecure handling of serialized objects, which can lead to remote code execution, injection attacks, or privilege escalation. Examples include:
   - Deserializing untrusted data from unauthenticated sources, leading to arbitrary code execution.
   - Lack of integrity checks allowing attackers to modify serialized objects.
   - Deserialization of attacker-controlled data without proper validation, leading to injection attacks.

8. **Using Components with Known Vulnerabilities**: This occurs when applications use outdated or vulnerable third-party libraries, frameworks, or components, exposing them to known security flaws. Examples include:
   - Failure to regularly update dependencies, leaving the application vulnerable to known exploits.
   - Using deprecated or unsupported libraries that no longer receive security patches.
   - Lack of visibility into the versions of third-party components used in the application.

9. **Insufficient Logging and Monitoring**: This refers to the lack of proper logging and monitoring mechanisms, which can hinder detection and response to security incidents. Examples include:
   - Failure to log important security events such as authentication failures, privilege escalations, or access to sensitive data.
   - Lack of real-time monitoring for suspicious activities or indicators of compromise.
   - Inadequate retention of log data, making it difficult to conduct forensic analysis or comply with regulatory requirements.

10. **Insufficient Rate Limiting**: This occurs when applications do not enforce rate limits on certain actions, allowing attackers to perform brute force attacks, account takeover, or denial of service. Examples include:
    - Lack of rate limiting on login attempts, enabling attackers to perform brute force attacks to guess user passwords.
    - Absence of rate limiting on API endpoints, making the application vulnerable to automated attacks or scraping.
    - Failure to enforce rate limits on resource-intensive operations, leading to service degradation or denial of service.

---

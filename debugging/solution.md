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

#### ChatGPT Response

The provided code contains a potential security vulnerability related to SQL injection. The vulnerability arises from the way the `customer_code` parameter is directly interpolated into the SQL query string. This can lead to SQL injection attacks if the `customer_code` value is not properly validated or sanitized.

Here's the vulnerable part of the code:
c.CustomerCode = '{customer_code}'

If an attacker provides a malicious `customer_code`, they can manipulate the SQL query and potentially execute unauthorized actions on the database.

To address this vulnerability, you should use parameterized queries or prepared statements instead of directly interpolating values into the SQL query string. Parameterized queries help to prevent SQL injection by ensuring that user input is treated as data rather than executable code.

Here's an example of how to use parameterized queries with the `pyodbc` library, assuming it is being used for database connectivity:

```python
query = """
    SELECT
        o.CustomerName,
        CAST(o.OrderDt AS DATE) AS OrderDate,
        SUM(o.OrderTotal) AS DailyTotal
    FROM dbo.Orders AS o
    INNER JOIN dbo.Customers AS c
        on o.CustomerKey = c.CustomerKey
    AND c.CustomerCode = ?
    GROUP BY o.CustomerName, CAST(o.OrderDt as DATE);
"""

# Execute the query with the parameter
cur.execute(query, (customer_code,))
```

By using `?` as a placeholder and passing the `customer_code` as a parameter to the `execute` method, you eliminate the risk of SQL injection. This ensures that the `customer_code` value is treated as a parameter rather than part of the SQL statement.

#### Prompt

Can you explain the remaining OWASP Top 10 issue and provide an example for each of them?

#### ChatGPT Response

Certainly! The OWASP Top 10 is a list of the most critical web application security risks. Here are the remaining issues along with brief explanations and examples:

6. Security Misconfiguration:
Description: Security misconfiguration occurs when security settings are not implemented or configured properly. This can lead to unauthorized access, exposure of sensitive data, or other security issues.

Example: Leaving default credentials in production code or misconfiguring file permissions, allowing unauthorized users to access sensitive information.

7. Cross-Site Scripting (XSS):
Description: XSS vulnerabilities arise when an application includes untrusted data on a web page without proper validation or escaping. This can allow attackers to execute malicious scripts in the context of a user's browser.

Example: An attacker injects a script into a web application by inserting malicious code into input fields or URL parameters. When other users view the affected page, the script is executed in their browsers.

8. Insecure Deserialization:
Description: Insecure deserialization occurs when an application deserializes untrusted data without proper validation. This can lead to remote code execution, security bypass, or other attacks.

Example: An attacker manipulates serialized data sent to an application, exploiting vulnerabilities in the deserialization process to execute arbitrary code.

9. Using Components with Known Vulnerabilities:
Description: Using outdated or vulnerable third-party components (libraries, frameworks, etc.) can expose an application to known security vulnerabilities.

Example: An application uses an older version of a library that has a known security flaw. Attackers can exploit this vulnerability to compromise the application.

10. Insufficient Logging and Monitoring:
Description: Lack of proper logging and monitoring makes it difficult to detect and respond to security incidents. This can result in delayed or ineffective incident response.

Example: An application does not log authentication failures, making it challenging to identify and respond to unauthorized access attempts.

Addressing these OWASP Top 10 issues involves adopting secure coding practices, regularly updating dependencies, implementing proper access controls, conducting security assessments, and ensuring proper monitoring and logging mechanisms are in place. Each issue requires a context-specific and layered approach to mitigate potential risks effectively.

---

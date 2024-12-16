# Joy Sketching in the Matrix

## Problem

<details>

<summary>Description</summary>

Joy is a big fan of the Matrix. She has this DVD which contains hidden easter eggs from the actors of the Matrix, especially the 8x16 version. Can you find out the easter egg?

Note: Format flag adalah FindITCTF{string} dengan kapitalisasi sesuai seperti petunjuk (lowercase)



</details>

## Solution

Initially when we take a look at the ‘chall’ file, the first thought was that it was some sort of hexdump of a binary file and we need to convert it to an executable before reversing it. And then there was a hunch telling that it was just a basic hex encoding applied to it. We then headed over to [CyberChef](https://gchq.github.io/CyberChef/) to decode it and our hunch quickly revealed that it's a source code.

<figure><img src="../../../.gitbook/assets/Screenshot 2023-05-15 094529.png" alt="" width="563"><figcaption></figcaption></figure>

By thoroughly inspecting the source code, it became evident that the code was an Arduino Sketch. Our analysis revealed that its purpose was to display content on an 8x16 LED matrix. To simplify the process, we considered an alternative approach using Python's Turtle module. Consequently, we swiftly developed a Python program utilising Turtle, which would dynamically move based on the input obtained from the cmd.txt file. `u` for moving upwards, `d` for down, `r` for right and `l` for left

From this point onward, most of the solution is handled by Aeryx since he has the most experience in terms of dealing with Arduino. Below is the python implementation code.

{% code title="go_turtle_go.py" lineNumbers="true" %}
```python
import turtle


def draw_text_formation(string_array):
   turtle.setup(width=1400, height=100)  # Set the window width to 1400 pixels


   turtle.hideturtle() # hide turtle
   turtle.speed(0)


   window_width = turtle.window_width() # Get the window width
   window_height = turtle.window_height() # Get the window height
   turtle.penup() # Pull the pen up
   # Set the initial position of the turtle
   turtle.goto(-window_width / 2 + 30, -window_height / 2 + 30)
   turtle.pendown() # Pull the pen down


   for string in string_array:
       start_position = turtle.position()  # Store the starting position of the string
      
       for char in string:
           if char == 'u':
               turtle.setheading(90)  # Face upwards
               turtle.forward(3)     # Move up by 3 units
           elif char == 'r':
               turtle.setheading(0)   # Face right
               turtle.forward(3)     # Move right by 3 units
           elif char == 'd':
               turtle.setheading(270) # Face downwards
               turtle.forward(3)     # Move down by 3 units
           elif char == 'l':
               turtle.setheading(180) # Face left
               turtle.forward(3)     # Move left by 3 units
      
       # Teleport to the right while maintaining the y-axis position
       turtle.penup()
       turtle.goto(start_position[0] + 30, start_position[1])
       turtle.pendown()
  
   turtle.done()


# read string from cmd file where splitted by new line
strings = []
with open('cmd.txt', 'r') as f:
   for line in f:
       strings.append(line.strip())


draw_text_formation(strings)
```
{% endcode %}

<figure><img src="../../../.gitbook/assets/WhatsApp Image 2023-05-14 at 15.33.28 (1).jpg" alt=""><figcaption><p>Sketch Output</p></figcaption></figure>

## Flag

> _**FindITCTF{etch\_the\_joysketch\_in\_the\_matrix\_zwquomf}**_

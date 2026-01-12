.class public final Landroidx/appcompat/view/menu/on;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/on$b;,
        Landroidx/appcompat/view/menu/on$a;
    }
.end annotation


# instance fields
.field public final a:Landroidx/appcompat/view/menu/on$b;

.field public b:I

.field public c:I


# direct methods
.method public constructor <init>(Landroid/widget/EditText;Z)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const v0, 0x7fffffff

    iput v0, p0, Landroidx/appcompat/view/menu/on;->b:I

    const/4 v0, 0x0

    iput v0, p0, Landroidx/appcompat/view/menu/on;->c:I

    const-string v0, "editText cannot be null"

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/mj0;->h(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v0, Landroidx/appcompat/view/menu/on$a;

    invoke-direct {v0, p1, p2}, Landroidx/appcompat/view/menu/on$a;-><init>(Landroid/widget/EditText;Z)V

    iput-object v0, p0, Landroidx/appcompat/view/menu/on;->a:Landroidx/appcompat/view/menu/on$b;

    return-void
.end method


# virtual methods
.method public a(Landroid/text/method/KeyListener;)Landroid/text/method/KeyListener;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/on;->a:Landroidx/appcompat/view/menu/on$b;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/on$b;->a(Landroid/text/method/KeyListener;)Landroid/text/method/KeyListener;

    move-result-object p1

    return-object p1
.end method

.method public b(Landroid/view/inputmethod/InputConnection;Landroid/view/inputmethod/EditorInfo;)Landroid/view/inputmethod/InputConnection;
    .locals 1

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/on;->a:Landroidx/appcompat/view/menu/on$b;

    invoke-virtual {v0, p1, p2}, Landroidx/appcompat/view/menu/on$b;->b(Landroid/view/inputmethod/InputConnection;Landroid/view/inputmethod/EditorInfo;)Landroid/view/inputmethod/InputConnection;

    move-result-object p1

    return-object p1
.end method

.method public c(Z)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/on;->a:Landroidx/appcompat/view/menu/on$b;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/on$b;->c(Z)V

    return-void
.end method

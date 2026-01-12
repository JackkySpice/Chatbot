.class public Landroidx/appcompat/view/menu/s11$b;
.super Landroidx/appcompat/view/menu/p11;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/s11;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "b"
.end annotation


# instance fields
.field public a:Landroidx/appcompat/view/menu/s11;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/s11;)V
    .locals 0

    invoke-direct {p0}, Landroidx/appcompat/view/menu/p11;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/s11$b;->a:Landroidx/appcompat/view/menu/s11;

    return-void
.end method


# virtual methods
.method public c(Landroidx/appcompat/view/menu/o11;)V
    .locals 1

    iget-object p1, p0, Landroidx/appcompat/view/menu/s11$b;->a:Landroidx/appcompat/view/menu/s11;

    iget-boolean v0, p1, Landroidx/appcompat/view/menu/s11;->Y:Z

    if-nez v0, :cond_0

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/o11;->d0()V

    iget-object p1, p0, Landroidx/appcompat/view/menu/s11$b;->a:Landroidx/appcompat/view/menu/s11;

    const/4 v0, 0x1

    iput-boolean v0, p1, Landroidx/appcompat/view/menu/s11;->Y:Z

    :cond_0
    return-void
.end method

.method public e(Landroidx/appcompat/view/menu/o11;)V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/s11$b;->a:Landroidx/appcompat/view/menu/s11;

    iget v1, v0, Landroidx/appcompat/view/menu/s11;->X:I

    add-int/lit8 v1, v1, -0x1

    iput v1, v0, Landroidx/appcompat/view/menu/s11;->X:I

    if-nez v1, :cond_0

    const/4 v1, 0x0

    iput-boolean v1, v0, Landroidx/appcompat/view/menu/s11;->Y:Z

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/o11;->s()V

    :cond_0
    invoke-virtual {p1, p0}, Landroidx/appcompat/view/menu/o11;->S(Landroidx/appcompat/view/menu/o11$f;)Landroidx/appcompat/view/menu/o11;

    return-void
.end method

.class public Landroidx/appcompat/view/menu/rz0$a;
.super Landroidx/appcompat/view/menu/oz0;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/rz0;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/rz0;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/rz0;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/rz0$a;->a:Landroidx/appcompat/view/menu/rz0;

    invoke-direct {p0}, Landroidx/appcompat/view/menu/oz0;-><init>()V

    return-void
.end method


# virtual methods
.method public a(I)V
    .locals 1

    iget-object p1, p0, Landroidx/appcompat/view/menu/rz0$a;->a:Landroidx/appcompat/view/menu/rz0;

    const/4 v0, 0x1

    invoke-static {p1, v0}, Landroidx/appcompat/view/menu/rz0;->a(Landroidx/appcompat/view/menu/rz0;Z)Z

    iget-object p1, p0, Landroidx/appcompat/view/menu/rz0$a;->a:Landroidx/appcompat/view/menu/rz0;

    invoke-static {p1}, Landroidx/appcompat/view/menu/rz0;->b(Landroidx/appcompat/view/menu/rz0;)Ljava/lang/ref/WeakReference;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/rz0$b;

    if-eqz p1, :cond_0

    invoke-interface {p1}, Landroidx/appcompat/view/menu/rz0$b;->a()V

    :cond_0
    return-void
.end method

.method public b(Landroid/graphics/Typeface;Z)V
    .locals 0

    if-eqz p2, :cond_0

    return-void

    :cond_0
    iget-object p1, p0, Landroidx/appcompat/view/menu/rz0$a;->a:Landroidx/appcompat/view/menu/rz0;

    const/4 p2, 0x1

    invoke-static {p1, p2}, Landroidx/appcompat/view/menu/rz0;->a(Landroidx/appcompat/view/menu/rz0;Z)Z

    iget-object p1, p0, Landroidx/appcompat/view/menu/rz0$a;->a:Landroidx/appcompat/view/menu/rz0;

    invoke-static {p1}, Landroidx/appcompat/view/menu/rz0;->b(Landroidx/appcompat/view/menu/rz0;)Ljava/lang/ref/WeakReference;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroidx/appcompat/view/menu/rz0$b;

    if-eqz p1, :cond_1

    invoke-interface {p1}, Landroidx/appcompat/view/menu/rz0$b;->a()V

    :cond_1
    return-void
.end method

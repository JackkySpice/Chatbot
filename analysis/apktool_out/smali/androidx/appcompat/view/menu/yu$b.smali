.class public Landroidx/appcompat/view/menu/yu$b;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/of;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/yu;->d(Landroid/content/Context;Landroidx/appcompat/view/menu/wu;ILjava/util/concurrent/Executor;Landroidx/appcompat/view/menu/o9;)Landroid/graphics/Typeface;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/o9;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/o9;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/yu$b;->a:Landroidx/appcompat/view/menu/o9;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a(Landroidx/appcompat/view/menu/yu$e;)V
    .locals 1

    if-nez p1, :cond_0

    new-instance p1, Landroidx/appcompat/view/menu/yu$e;

    const/4 v0, -0x3

    invoke-direct {p1, v0}, Landroidx/appcompat/view/menu/yu$e;-><init>(I)V

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/yu$b;->a:Landroidx/appcompat/view/menu/o9;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/o9;->b(Landroidx/appcompat/view/menu/yu$e;)V

    return-void
.end method

.method public bridge synthetic accept(Ljava/lang/Object;)V
    .locals 0

    check-cast p1, Landroidx/appcompat/view/menu/yu$e;

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/yu$b;->a(Landroidx/appcompat/view/menu/yu$e;)V

    return-void
.end method

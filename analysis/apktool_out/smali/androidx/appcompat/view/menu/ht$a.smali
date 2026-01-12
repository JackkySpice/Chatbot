.class public Landroidx/appcompat/view/menu/ht$a;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/window/OnBackAnimationCallback;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Landroidx/appcompat/view/menu/ht;->M()Landroid/window/OnBackInvokedCallback;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/ht;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/ht;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/ht$a;->a:Landroidx/appcompat/view/menu/ht;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public onBackCancelled()V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ht$a;->a:Landroidx/appcompat/view/menu/ht;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ht;->H()V

    return-void
.end method

.method public onBackInvoked()V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ht$a;->a:Landroidx/appcompat/view/menu/ht;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ht;->I()V

    return-void
.end method

.method public onBackProgressed(Landroid/window/BackEvent;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ht$a;->a:Landroidx/appcompat/view/menu/ht;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/ht;->X(Landroid/window/BackEvent;)V

    return-void
.end method

.method public onBackStarted(Landroid/window/BackEvent;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ht$a;->a:Landroidx/appcompat/view/menu/ht;

    invoke-virtual {v0, p1}, Landroidx/appcompat/view/menu/ht;->T(Landroid/window/BackEvent;)V

    return-void
.end method

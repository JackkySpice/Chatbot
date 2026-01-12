.class public final synthetic Landroidx/appcompat/view/menu/gt;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/window/OnBackInvokedCallback;


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/ht;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/ht;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/gt;->a:Landroidx/appcompat/view/menu/ht;

    return-void
.end method


# virtual methods
.method public final onBackInvoked()V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/gt;->a:Landroidx/appcompat/view/menu/ht;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ht;->onBackPressed()V

    return-void
.end method
